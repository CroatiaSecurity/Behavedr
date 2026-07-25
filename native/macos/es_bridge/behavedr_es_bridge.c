/*
 * Behavedr EndpointSecurity bridge dylib.
 * Exports C ABI for .NET P/Invoke (blocks cannot be authored cleanly from pure C#).
 *
 * Build (macOS):
 *   clang -dynamiclib -o libbehavedr_es.dylib behavedr_es_bridge.c \
 *     -framework EndpointSecurity -framework CoreFoundation
 *   sudo cp libbehavedr_es.dylib /opt/behavedr/
 *
 * Requires: root + com.apple.developer.endpoint-security.client entitlement on the
 * host agent (or system extension packaging — see packaging/unix/macos-endpointsecurity.md).
 */
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libproc.h>

typedef void (*behavedr_es_cb)(const char *kind, int pid, const char *process_name, const char *path);

static es_client_t *g_client = NULL;
static behavedr_es_cb g_cb = NULL;

static void get_proc_name(pid_t pid, char *buf, size_t len)
{
    if (proc_name(pid, buf, (uint32_t)len) <= 0)
        snprintf(buf, len, "pid-%d", (int)pid);
}

static void handle_msg(es_client_t *client, const es_message_t *msg)
{
    (void)client;
    if (!g_cb || !msg || !msg->process)
        return;

    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    char name[64];
    get_proc_name(pid, name, sizeof(name));

    const char *kind = "event";
    char pathbuf[1024];
    pathbuf[0] = '\0';

    switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        kind = "exec";
        if (msg->event.exec.target && msg->event.exec.target->executable) {
            es_string_token_t p = msg->event.exec.target->executable->path;
            if (p.data && p.length > 0) {
                size_t n = p.length < sizeof(pathbuf) - 1 ? p.length : sizeof(pathbuf) - 1;
                memcpy(pathbuf, p.data, n);
                pathbuf[n] = '\0';
            }
        }
        break;
    case ES_EVENT_TYPE_NOTIFY_FORK:
        kind = "fork";
        break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        kind = "exit";
        break;
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        kind = "open";
        if (msg->event.open.file) {
            es_string_token_t p = msg->event.open.file->path;
            if (p.data && p.length > 0) {
                size_t n = p.length < sizeof(pathbuf) - 1 ? p.length : sizeof(pathbuf) - 1;
                memcpy(pathbuf, p.data, n);
                pathbuf[n] = '\0';
            }
        }
        break;
    default:
        break;
    }

    g_cb(kind, (int)pid, name, pathbuf);
}

int behavedr_es_create(behavedr_es_cb cb, es_client_t **out_client)
{
    if (!cb || !out_client)
        return -1;
    g_cb = cb;
    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handle_msg(c, m);
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        *out_client = NULL;
        return (int)res;
    }
    *out_client = g_client;
    return 0;
}

int behavedr_es_subscribe(es_client_t *client, const uint32_t *events, int count)
{
    if (!client || !events || count <= 0)
        return -1;
    es_event_type_t *types = calloc((size_t)count, sizeof(es_event_type_t));
    if (!types)
        return -1;
    for (int i = 0; i < count; i++)
        types[i] = (es_event_type_t)events[i];
    es_return_t r = es_subscribe(client, types, (uint32_t)count);
    free(types);
    return r == ES_RETURN_SUCCESS ? 0 : -2;
}

void behavedr_es_delete(es_client_t *client)
{
    if (client)
        es_delete_client(client);
    if (client == g_client)
        g_client = NULL;
}
