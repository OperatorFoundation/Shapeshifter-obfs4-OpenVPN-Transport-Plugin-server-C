#pragma once
#define _WINSOCKAPI_    // stops windows.h including winsock.h

#include "shapeshifter-obfs4.h"
#include "Shapeshifter-obfs4-OpenVPN-Transport-Plugin-server-Cgo.h"
#include "openvpn-vsocket.h"
#include "openvpn-plugin.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <winsock2.h>
#include <windows.h>

#include <assert.h>

static inline bool is_invalid_handle(HANDLE h)
{
    return h == NULL || h == INVALID_HANDLE_VALUE;
}

struct shapeshifter_obfs4_socket_win32
{
    struct openvpn_vsocket_handle handle;
    struct shapeshifter_obfs4_context *ctx;

    /* Write is ready when idle; read is not-ready when idle. Both level-triggered. */
    struct openvpn_vsocket_win32_event_pair completion_events;
    unsigned last_rwflags;

    // obfs4
    GoInt server_id;
};

struct openvpn_vsocket_vtab shapeshifter_obfs4_socket_vtab;

static void free_socket(struct shapeshifter_obfs4_socket_win32 *sock)
{
    if (!sock)
        return;

    if (!is_invalid_handle(sock->completion_events.read)) {
        CloseHandle(sock->completion_events.read);
    }

    if (!is_invalid_handle(sock->completion_events.write)){
        CloseHandle(sock->completion_events.write);
    }

    Obfs4_close_connection(sock->server_id);

    free(sock);
}

static openvpn_vsocket_handle_t shapeshifter_obfs4_win32_bind(void *plugin_handle, const struct sockaddr *addr, openvpn_vsocket_socklen_t len)
{
    struct shapeshifter_obfs4_socket_win32 *sock = NULL;

    sock = calloc(1, sizeof(struct shapeshifter_obfs4_socket_win32));
    if (!sock)
        goto error;

    sock->handle.vtab = &shapeshifter_obfs4_socket_vtab;
    sock->ctx = (struct shapeshifter_obfs4_context *) plugin_handle;

    // Create an obfs4 client.
    sock->server_id = Obfs4_initialize_server(sock->ctx->state_dir);

    /* See above: write is ready when idle, read is not-ready when idle. */
    sock->completion_events.read = CreateEvent(NULL, TRUE, FALSE, NULL);
    sock->completion_events.write = CreateEvent(NULL, TRUE, TRUE, NULL);

    if (is_invalid_handle(sock->completion_events.read) || is_invalid_handle(sock->completion_events.write))
        goto error;

    //FIXME: This only works for ipv4 addresses, need to address ipv6
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    Obfs4_listen(sock->server_id, inet_ntoa(addr_in->sin_addr));
    Obfs4_accept(sock->server_id);
    
    return &sock->handle;

    error:
        shapeshifter_obfs4_log((struct shapeshifter_obfs4_context *) plugin_handle, PLOG_ERR,
                      "bind failure: WSA error = %d", WSAGetLastError());
        free_socket(sock);
        return NULL;
}

static void shapeshifter_obfs4_win32_request_event(openvpn_vsocket_handle_t handle, openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_win32 *)handle)->ctx, PLOG_DEBUG, "request-event: %d", rwflags);
    ((struct shapeshifter_obfs4_socket_win32 *)handle)->last_rwflags = 0;

    if (rwflags) {
        event_set->vtab->set_event(event_set, &sock->completion_events, rwflags,
                                   handle);
    }
}

static bool shapeshifter_obfs4_win32_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_win32 *) handle)->ctx, PLOG_DEBUG,
                  "update-event: %p, %p, %d", handle, arg, rwflags);
    if (arg != handle) {
        return false;
    }

    ((struct shapeshifter_obfs4_socket_win32 *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned shapeshifter_obfs4_win32_pump(openvpn_vsocket_handle_t handle)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    unsigned result = 0;

    if ((sock->last_rwflags & OPENVPN_VSOCKET_EVENT_READ)) {
        result |= OPENVPN_VSOCKET_EVENT_READ;
    }

    if ((sock->last_rwflags & OPENVPN_VSOCKET_EVENT_WRITE)) {
        result |= OPENVPN_VSOCKET_EVENT_WRITE;
    }

    shapeshifter_obfs4_log(sock->ctx, PLOG_DEBUG, "pump -> %d", result);

    return result;
}

static ssize_t shapeshifter_obfs4_win32_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len, struct sockaddr *addr, openvpn_vsocket_socklen_t *addrlen)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    GoInt server_id = sock->server_id;
    GoInt number_of_bytes_read = Obfs4_read(server_id, (void *)buf, (int)len);

    if (number_of_bytes_read < 0)
    {
        return -1;
    }

    ResetEvent(sock->completion_events.read);

    // FIXME: We may need to assign something to *addr

    return number_of_bytes_read;
}

static ssize_t shapeshifter_obfs4_win32_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len, const struct sockaddr *addr, openvpn_vsocket_socklen_t addrlen)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    GoInt server_id = sock->server_id;
    GoInt number_of_characters_sent = Obfs4_write(server_id, (void *)buf, (int)len);

    if (number_of_characters_sent < 0)
    {
        goto error;
    }

    SetEvent(sock->completion_events.write);

    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_win32 *) handle)->ctx, PLOG_DEBUG, "sendto(%d) -> %d", (int)len, (int)number_of_characters_sent);

    return number_of_characters_sent;

    error:
        return -1;
}

static void shapeshifter_obfs4_win32_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct shapeshifter_obfs4_socket_win32 *) handle);
}

void
shapeshifter_obfs4_initialize_socket_vtab(void)
{
    shapeshifter_obfs4_socket_vtab.bind = shapeshifter_obfs4_win32_bind;
    shapeshifter_obfs4_socket_vtab.request_event = shapeshifter_obfs4_win32_request_event;
    shapeshifter_obfs4_socket_vtab.update_event = shapeshifter_obfs4_win32_update_event;
    shapeshifter_obfs4_socket_vtab.pump = shapeshifter_obfs4_win32_pump;
    shapeshifter_obfs4_socket_vtab.recvfrom = shapeshifter_obfs4_win32_recvfrom;
    shapeshifter_obfs4_socket_vtab.sendto = shapeshifter_obfs4_win32_sendto;
    shapeshifter_obfs4_socket_vtab.close = shapeshifter_obfs4_win32_close;
}
