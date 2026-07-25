/*
 * Behavedr EndpointSecurity bridge — production C ABI (0.3.3)
 *
 * Design:
 *  - ES messages are handled on the ES callback thread only.
 *  - Events are copied into a fixed SPSC ring buffer (no managed callback from ES).
 *  - Managed code polls via behavedr_es_poll.
 *  - AUTH events are answered on the callback thread (required by ES deadline).
 *  - AUTH DENY only when g_auth_mode is set AND path matches conservative denylist.
 *
 * Build:
 *   clang -dynamiclib -O2 -o libbehavedr_es.dylib behavedr_es_bridge.c \
 *     -framework EndpointSecurity -framework CoreFoundation
 *   install_name_tool -id @rpath/libbehavedr_es.dylib libbehavedr_es.dylib
 *   sudo cp libbehavedr_es.dylib /opt/behavedr/
 *
 * Requires: root + com.apple.developer.endpoint-security.client
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BEHAVEDR_ES_RING 4096
#define BEHAVEDR_ES_KIND 32
#define BEHAVEDR_ES_NAME 64
#define BEHAVEDR_ES_PATH 512

typedef struct {
    char kind[BEHAVEDR_ES_KIND];
    int pid;
    char name[BEHAVEDR_ES_NAME];
    char path[BEHAVEDR_ES_PATH];
} behavedr_es_event;

static es_client_t *g_client = NULL;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static behavedr_es_event g_ring[BEHAVEDR_ES_RING];
/* SPSC: producer = ES callback thread, consumer = poll thread */
static atomic_uint g_head = 0; /* write index (producer) */
static atomic_uint g_tail = 0; /* read index (consumer) */
static atomic_int g_auth_mode = 0;
static atomic_int g_muted_self = 0;
static atomic_ullong g_dropped = 0;
static atomic_ullong g_enqueued = 0;
static atomic_ullong g_auth_denied = 0;

static void get_proc_name(pid_t pid, char *buf, size_t len)
{
    if (proc_name(pid, buf, (uint32_t)len) <= 0)
        snprintf(buf, len, "pid-%d", (int)pid);
}

static int path_is_denylisted(const char *path)
{
    if (!path || !path[0])
        return 0;
    /* Conservative AUTH denylist — high-confidence droppers only */
    if (strncmp(path, "/tmp/", 5) == 0) return 1;
    if (strncmp(path, "/private/tmp/", 13) == 0) return 1;
    if (strncmp(path, "/var/tmp/", 9) == 0) return 1;
    if (strncmp(path, "/private/var/tmp/", 17) == 0) return 1;
    if (strstr(path, "mimikatz") != NULL) return 1;
    if (strstr(path, "meterpreter") != NULL) return 1;
    if (strstr(path, "sliver") != NULL) return 1;
    if (strstr(path, "cobaltstrike") != NULL) return 1;
    if (strstr(path, "/Users/Shared/") != NULL && strstr(path, ".dmg") != NULL) return 1;
    return 0;
}

static void copy_token(char *dst, size_t dstlen, es_string_token_t tok)
{
    if (!dst || dstlen == 0) return;
    dst[0] = '\0';
    if (!tok.data || tok.length == 0) return;
    size_t n = tok.length < dstlen - 1 ? tok.length : dstlen - 1;
    memcpy(dst, tok.data, n);
    dst[n] = '\0';
}

static void enqueue(const char *kind, int pid, const char *name, const char *path)
{
    uint32_t head = atomic_load_explicit(&g_head, memory_order_relaxed);
    uint32_t next = (head + 1u) % BEHAVEDR_ES_RING;
    uint32_t tail = atomic_load_explicit(&g_tail, memory_order_acquire);
    if (next == tail) {
        /* ring full — drop oldest to keep newest telemetry */
        atomic_store_explicit(&g_tail, (tail + 1u) % BEHAVEDR_ES_RING, memory_order_release);
        atomic_fetch_add_explicit(&g_dropped, 1, memory_order_relaxed);
    }

    behavedr_es_event *e = &g_ring[head];
    memset(e, 0, sizeof(*e));
    if (kind) {
        strncpy(e->kind, kind, BEHAVEDR_ES_KIND - 1);
        e->kind[BEHAVEDR_ES_KIND - 1] = '\0';
    }
    e->pid = pid;
    if (name) {
        strncpy(e->name, name, BEHAVEDR_ES_NAME - 1);
        e->name[BEHAVEDR_ES_NAME - 1] = '\0';
    }
    if (path) {
        strncpy(e->path, path, BEHAVEDR_ES_PATH - 1);
        e->path[BEHAVEDR_ES_PATH - 1] = '\0';
    }
    atomic_store_explicit(&g_head, next, memory_order_release);
    atomic_fetch_add_explicit(&g_enqueued, 1, memory_order_relaxed);
}

static void handle_msg(es_client_t *client, const es_message_t *msg)
{
    if (!msg || !msg->process)
        return;

    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    if (atomic_load_explicit(&g_muted_self, memory_order_relaxed) && pid == getpid()) {
        /* Still must respond to AUTH for our own process if subscribed */
        if (msg->action_type == ES_ACTION_TYPE_AUTH) {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        }
        return;
    }

    char name[BEHAVEDR_ES_NAME];
    get_proc_name(pid, name, sizeof(name));

    const char *kind = "event";
    char pathbuf[BEHAVEDR_ES_PATH];
    pathbuf[0] = '\0';
    int is_auth = 0;

    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
        is_auth = 1;
        kind = "auth_exec";
        if (msg->event.exec.target && msg->event.exec.target->executable)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.exec.target->executable->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        kind = "exec";
        if (msg->event.exec.target && msg->event.exec.target->executable)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.exec.target->executable->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_FORK:
        kind = "fork";
        break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        kind = "exit";
        break;
    case ES_EVENT_TYPE_AUTH_OPEN:
        is_auth = 1;
        kind = "auth_open";
        if (msg->event.open.file)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.open.file->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        kind = "open";
        if (msg->event.open.file)
            copy_token(pathbuf, sizeof(pathbuf), msg->event.open.file->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_CREATE:
        kind = "create";
        break;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        kind = "rename";
        break;
    case ES_EVENT_TYPE_NOTIFY_WRITE:
        kind = "write";
        break;
    default:
        break;
    }

    enqueue(kind, (int)pid, name, pathbuf);

    if (is_auth) {
        es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
        if (atomic_load_explicit(&g_auth_mode, memory_order_relaxed) &&
            path_is_denylisted(pathbuf)) {
            result = ES_AUTH_RESULT_DENY;
            atomic_fetch_add_explicit(&g_auth_denied, 1, memory_order_relaxed);
            enqueue("auth_denied", (int)pid, name, pathbuf);
        }
        es_respond_auth_result(client, msg, result, false);
    }
}

/* ===== exported ABI ===== */

int behavedr_es_create(void **out_client)
{
    if (!out_client)
        return -1;
    *out_client = NULL;

    pthread_mutex_lock(&g_mu);
    if (g_client) {
        *out_client = g_client;
        pthread_mutex_unlock(&g_mu);
        return 0;
    }

    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handle_msg(c, m);
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        g_client = NULL;
        pthread_mutex_unlock(&g_mu);
        return (int)res;
    }

    /* Mute our own process tree prefix to reduce noise (best-effort) */
    es_mute_path(g_client, "/opt/behavedr/", ES_MUTE_PATH_TYPE_PREFIX);
    atomic_store_explicit(&g_muted_self, 1, memory_order_relaxed);

    *out_client = g_client;
    pthread_mutex_unlock(&g_mu);
    return 0;
}

int behavedr_es_set_auth_mode(int enabled)
{
    atomic_store_explicit(&g_auth_mode, enabled ? 1 : 0, memory_order_relaxed);
    return 0;
}

int behavedr_es_subscribe(void *client, const uint32_t *events, int count)
{
    if (!client || !events || count <= 0)
        return -1;

    es_event_type_t *types = calloc((size_t)count, sizeof(es_event_type_t));
    if (!types)
        return -1;
    for (int i = 0; i < count; i++)
        types[i] = (es_event_type_t)events[i];

    es_return_t r = es_subscribe((es_client_t *)client, types, (uint32_t)count);
    free(types);
    return r == ES_RETURN_SUCCESS ? 0 : -2;
}

/* Returns 1 if event dequeued, 0 if empty, <0 on error */
int behavedr_es_poll(char *kind, int kind_len,
                     int *pid,
                     char *name, int name_len,
                     char *path, int path_len)
{
    if (!kind || kind_len <= 0 || !pid || !name || name_len <= 0 || !path || path_len <= 0)
        return -1;

    uint32_t tail = atomic_load_explicit(&g_tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&g_head, memory_order_acquire);
    if (tail == head)
        return 0;

    behavedr_es_event *e = &g_ring[tail];
    strncpy(kind, e->kind, (size_t)kind_len - 1);
    kind[kind_len - 1] = '\0';
    *pid = e->pid;
    strncpy(name, e->name, (size_t)name_len - 1);
    name[name_len - 1] = '\0';
    strncpy(path, e->path, (size_t)path_len - 1);
    path[path_len - 1] = '\0';

    atomic_store_explicit(&g_tail, (tail + 1u) % BEHAVEDR_ES_RING, memory_order_release);
    return 1;
}

int behavedr_es_pending(void)
{
    uint32_t head = atomic_load_explicit(&g_head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&g_tail, memory_order_relaxed);
    if (head >= tail)
        return (int)(head - tail);
    return (int)(BEHAVEDR_ES_RING - tail + head);
}

/* Stats for operators / SE host (optional) */
int behavedr_es_stats(unsigned long long *enqueued,
                      unsigned long long *dropped,
                      unsigned long long *auth_denied)
{
    if (enqueued)
        *enqueued = atomic_load_explicit(&g_enqueued, memory_order_relaxed);
    if (dropped)
        *dropped = atomic_load_explicit(&g_dropped, memory_order_relaxed);
    if (auth_denied)
        *auth_denied = atomic_load_explicit(&g_auth_denied, memory_order_relaxed);
    return 0;
}

void behavedr_es_delete(void *client)
{
    pthread_mutex_lock(&g_mu);
    if (client)
        es_delete_client((es_client_t *)client);
    if (client == g_client)
        g_client = NULL;
    atomic_store_explicit(&g_head, 0, memory_order_relaxed);
    atomic_store_explicit(&g_tail, 0, memory_order_relaxed);
    pthread_mutex_unlock(&g_mu);
}

/* Back-compat: ignore callback, create client the same way */
typedef void (*behavedr_es_cb)(const char *, int, const char *, const char *);
int behavedr_es_create_cb(behavedr_es_cb cb, void **out_client)
{
    (void)cb;
    return behavedr_es_create(out_client);
}
