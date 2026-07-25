/*
 * Behavedr Endpoint Security System Extension host (0.3.2).
 * Minimal ES client that logs EXEC events; production should XPC to the agent.
 *
 * Build: ./build.sh (macOS + EndpointSecurity.framework + signing identity)
 */
#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static es_client_t *g_client = NULL;
static volatile sig_atomic_t g_stop = 0;

static void on_sig(int s) { (void)s; g_stop = 1; }

static void handle_msg(es_client_t *client, const es_message_t *msg)
{
    (void)client;
    if (!msg || !msg->process) return;
    pid_t pid = audit_token_to_pid(msg->process->audit_token);
    char name[64] = {0};
    proc_name(pid, name, sizeof(name));
    const char *kind = "event";
    switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC: kind = "exec"; break;
    case ES_EVENT_TYPE_NOTIFY_FORK: kind = "fork"; break;
    case ES_EVENT_TYPE_NOTIFY_EXIT: kind = "exit"; break;
    case ES_EVENT_TYPE_NOTIFY_OPEN: kind = "open"; break;
    case ES_EVENT_TYPE_AUTH_EXEC:
        kind = "auth_exec";
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        break;
    case ES_EVENT_TYPE_AUTH_OPEN:
        kind = "auth_open";
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        break;
    default: break;
    }
    fprintf(stderr, "[BehavedrES] %s pid=%d name=%s\n", kind, (int)pid, name);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    es_new_client_result_t res = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handle_msg(c, m);
    });
    if (res != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "[BehavedrES] es_new_client failed: %d\n", (int)res);
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_OPEN,
    };
    if (es_subscribe(g_client, events, sizeof(events)/sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "[BehavedrES] es_subscribe failed\n");
        es_delete_client(g_client);
        return 2;
    }

    fprintf(stderr, "[BehavedrES] subscribed — running\n");
    while (!g_stop) sleep(1);

    es_delete_client(g_client);
    return 0;
}
