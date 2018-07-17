#include "shapeshifter-obfs4.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <winsock2.h>
#include <assert.h>

static inline bool
is_invalid_handle(HANDLE h)
{
    return h == NULL || h == INVALID_HANDLE_VALUE;
}

typedef enum {
    IO_SLOT_DORMANT,            /* must be 0 for calloc purposes */
    IO_SLOT_PENDING,
    /* success/failure is determined by succeeded flag in COMPLETE state */
    IO_SLOT_COMPLETE
} io_slot_status_t;

/* must be calloc'able */
struct io_slot
{
    struct shapeshifter_obfs4_context *ctx;
    io_slot_status_t status;
    OVERLAPPED overlapped;
    SOCKET socket;
    SOCKADDR_STORAGE addr;
    int addr_len, addr_cap;
    DWORD bytes, flags;
    bool succeeded;
    int wsa_error;

    /* realloc'd as needed; always private copy, never aliased */
    char *buf;
    size_t buf_len, buf_cap;
};

static bool
setup_io_slot(struct io_slot *slot, struct shapeshifter_obfs4_context *ctx,
              SOCKET socket, HANDLE event)
{
    slot->ctx = ctx;
    slot->status = IO_SLOT_DORMANT;
    slot->addr_cap = sizeof(SOCKADDR_STORAGE);
    slot->socket = socket;
    slot->overlapped.hEvent = event;
    return true;
}

/* Note that this assumes any I/O has already been implicitly canceled (via closesocket),
   but not waited for yet. */
static bool
destroy_io_slot(struct io_slot *slot)
{
    if (slot->status == IO_SLOT_PENDING)
    {
        DWORD bytes, flags;
        BOOL ok = WSAGetOverlappedResult(slot->socket, &slot->overlapped, &bytes,
                                         TRUE /* wait */, &flags);
        if (!ok && WSAGetLastError() == WSA_IO_INCOMPLETE)
        {
            shapeshifter_obfs4_log(slot->ctx, PLOG_ERR,
                          "destroying I/O slot: canceled operation is still incomplete after wait?!");
            return false;
        }
    }

    slot->status = IO_SLOT_DORMANT;
    return true;
}

/* FIXME: aborts on error. */
static void
resize_io_buf(struct io_slot *slot, size_t cap)
{
    if (slot->buf)
    {
        free(slot->buf);
        slot->buf = NULL;
    }

    char *new_buf = malloc(cap);
    if (!new_buf)
        abort();
    slot->buf = new_buf;
    slot->buf_cap = cap;
}

struct shapeshifter_obfs4_socket_win32
{
    struct openvpn_vsocket_handle handle;
    struct shapeshifter_obfs4_context *ctx;
    SOCKET socket;

    /* Write is ready when idle; read is not-ready when idle. Both level-triggered. */
    struct openvpn_vsocket_win32_event_pair completion_events;
    struct io_slot slot_read, slot_write;

    int last_rwflags;
};

struct openvpn_vsocket_vtab shapeshifter_obfs4_socket_vtab;

static void
free_socket(struct shapeshifter_obfs4_socket_win32 *sock)
{
    /* This only ever becomes false in strange situations where we leak the entire structure for
       lack of anything else to do. */
    bool can_free = true;

    if (!sock)
        return;
    if (sock->socket != INVALID_SOCKET)
        closesocket(sock->socket);

    /* closesocket cancels any pending overlapped I/O, but we still have to potentially
       wait for it here before we can free the buffers. This has to happen before closing
       the event handles.

       If we can't figure out when the canceled overlapped I/O is done, for any reason, we defensively
       leak the entire structure; freeing it would be permitting the system to corrupt memory later.
       TODO: possibly abort() instead, but make sure we've handled all the possible "have to try again"
       cases above first
    */
    if (!destroy_io_slot(&sock->slot_read))
        can_free = false;
    if (!destroy_io_slot(&sock->slot_write))
        can_free = false;
    if (!can_free)
    {
        /* Skip deinitialization of everything else. Doomed. */
        shapeshifter_obfs4_log(sock->ctx, PLOG_ERR, "doomed, leaking the entire socket structure");
        return;
    }

    if (!is_invalid_handle(sock->completion_events.read))
        CloseHandle(sock->completion_events.read);
    if (!is_invalid_handle(sock->completion_events.write))
        CloseHandle(sock->completion_events.write);

    free(sock);
}

static openvpn_vsocket_handle_t
shapeshifter_obfs4_win32_bind(void *plugin_handle,
                     const struct sockaddr *addr, openvpn_vsocket_socklen_t len)
{
    struct shapeshifter_obfs4_socket_win32 *sock = NULL;
//    struct sockaddr *addr_rev = NULL;
//
//    /* TODO: would be nice to factor out some of these sequences */
//    addr_rev = calloc(1, len);
//    if (!addr_rev)
//        goto error;
//    memcpy(addr_rev, addr, len);
//    shapeshifter_obfs4_munge_addr(addr_rev, len);

    sock = calloc(1, sizeof(struct shapeshifter_obfs4_socket_win32));
    if (!sock)
        goto error;
    sock->handle.vtab = &shapeshifter_obfs4_socket_vtab;
    sock->ctx = (struct shapeshifter_obfs4_context *) plugin_handle;

    /* Preemptively initialize the members of some Win32 types so error exits are okay later on.
       HANDLEs of NULL are considered invalid per above. */
    sock->socket = INVALID_SOCKET;

    sock->socket = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->socket == INVALID_SOCKET)
        goto error;

    /* See above: write is ready when idle, read is not-ready when idle. */
    sock->completion_events.read = CreateEvent(NULL, TRUE, FALSE, NULL);
    sock->completion_events.write = CreateEvent(NULL, TRUE, TRUE, NULL);
    
    if (is_invalid_handle(sock->completion_events.read) || is_invalid_handle(sock->completion_events.write))
        goto error;
    
    if (!setup_io_slot(&sock->slot_read, sock->ctx,
                       sock->socket, sock->completion_events.read))
        goto error;
    
    if (!setup_io_slot(&sock->slot_write, sock->ctx,
                       sock->socket, sock->completion_events.write))
        goto error;

    if (bind(sock->socket, addr, len))
        goto error;

    return &sock->handle;

error:
    shapeshifter_obfs4_log((struct shapeshifter_obfs4_context *) plugin_handle, PLOG_ERR,
                  "bind failure: WSA error = %d", WSAGetLastError());
    free_socket(sock);
    return NULL;
}

static void
handle_sendrecv_return(struct io_slot *slot, int status)
{
    if (status == 0)
    {
        /* Immediately completed. Set the event so it stays consistent. */
        slot->status = IO_SLOT_COMPLETE;
        slot->succeeded = true;
        slot->buf_len = slot->bytes;
        SetEvent(slot->overlapped.hEvent);
    }
    else if (WSAGetLastError() == WSA_IO_PENDING)
    {
        /* Queued. */
        slot->status = IO_SLOT_PENDING;
    }
    else
    {
        /* Error. */
        slot->status = IO_SLOT_COMPLETE;
        slot->succeeded = false;
        slot->wsa_error = WSAGetLastError();
        slot->buf_len = 0;
    }
}

static void
queue_new_read(struct io_slot *slot, size_t cap)
{
    int status;
    WSABUF sbuf;
    assert(slot->status == IO_SLOT_DORMANT);

    ResetEvent(slot->overlapped.hEvent);
    resize_io_buf(slot, cap);
    sbuf.buf = slot->buf;
    sbuf.len = slot->buf_cap;
    slot->addr_len = slot->addr_cap;
    slot->flags = 0;
    status = WSARecvFrom(slot->socket, &sbuf, 1, &slot->bytes, &slot->flags,
                         (struct sockaddr *)&slot->addr, &slot->addr_len,
                         &slot->overlapped, NULL);
    handle_sendrecv_return(slot, status);
}

/* write slot buffer must already be full. */
static void
queue_new_write(struct io_slot *slot)
{
    int status;
    WSABUF sbuf;
    assert(slot->status == IO_SLOT_COMPLETE || slot->status == IO_SLOT_DORMANT);

    ResetEvent(slot->overlapped.hEvent);
    sbuf.buf = slot->buf;
    sbuf.len = slot->buf_len;
    slot->flags = 0;
    status = WSASendTo(slot->socket, &sbuf, 1, &slot->bytes, 0 /* flags */,
                       (struct sockaddr *)&slot->addr, slot->addr_len,
                       &slot->overlapped, NULL);
    handle_sendrecv_return(slot, status);
}

static void
ensure_pending_read(struct shapeshifter_obfs4_socket_win32 *sock)
{
    struct io_slot *slot = &sock->slot_read;
    switch (slot->status)
    {
        case IO_SLOT_PENDING:
            return;
        case IO_SLOT_COMPLETE:
            /* Set the event manually here just in case. */
            SetEvent(slot->overlapped.hEvent);
            return;

        case IO_SLOT_DORMANT:
            /* TODO: we don't propagate max read size here, so we just have to assume the maximum. */
            queue_new_read(slot, 65536);
            return;

        default:
            abort();
    }
}

static bool
complete_pending_operation(struct io_slot *slot)
{
    DWORD bytes, flags;
    BOOL ok;

    switch (slot->status)
    {
        case IO_SLOT_DORMANT:
            /* TODO: shouldn't get here? */
            return false;
        case IO_SLOT_COMPLETE:
            return true;

        case IO_SLOT_PENDING:
            ok = WSAGetOverlappedResult(slot->socket, &slot->overlapped, &bytes,
                                        FALSE /* don't wait */, &flags);
            if (!ok && WSAGetLastError() == WSA_IO_INCOMPLETE)
            {
                /* Still waiting. */
                return false;
            }
            else if (ok)
            {
                /* Completed. slot->addr_len has already been updated. */
                slot->buf_len = bytes;
                slot->status = IO_SLOT_COMPLETE;
                slot->succeeded = true;
                return true;
            }
            else
            {
                /* Error. */
                slot->buf_len = 0;
                slot->status = IO_SLOT_COMPLETE;
                slot->succeeded = false;
                slot->wsa_error = WSAGetLastError();
                return true;
            }

        default:
            abort();
    }
}

static bool
complete_pending_read(struct shapeshifter_obfs4_socket_win32 *sock)
{
    bool done = complete_pending_operation(&sock->slot_read);
    if (done)
        ResetEvent(sock->completion_events.read);
    return done;
}

static void
consumed_pending_read(struct shapeshifter_obfs4_socket_win32 *sock)
{
    struct io_slot *slot = &sock->slot_read;
    assert(slot->status == IO_SLOT_COMPLETE);
    slot->status = IO_SLOT_DORMANT;
    slot->succeeded = false;
    ResetEvent(slot->overlapped.hEvent);
}

static inline bool
complete_pending_write(struct shapeshifter_obfs4_socket_win32 *sock)
{
    bool done = complete_pending_operation(&sock->slot_write);
    if (done)
        SetEvent(sock->completion_events.write);
    return done;
}

static void
shapeshifter_obfs4_win32_request_event(openvpn_vsocket_handle_t handle,
                              openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    shapeshifter_obfs4_log(sock->ctx, PLOG_DEBUG, "request-event: %d", rwflags);
    sock->last_rwflags = 0;

    if (rwflags & OPENVPN_VSOCKET_EVENT_READ)
        ensure_pending_read(sock);
    if (rwflags)
        event_set->vtab->set_event(event_set, &sock->completion_events, rwflags, handle);
}

static bool
shapeshifter_obfs4_win32_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_win32 *) handle)->ctx, PLOG_DEBUG,
                  "update-event: %p, %p, %d", handle, arg, rwflags);
    if (arg != handle)
        return false;
    ((struct shapeshifter_obfs4_socket_win32 *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned
shapeshifter_obfs4_win32_pump(openvpn_vsocket_handle_t handle)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    unsigned result = 0;

    if ((sock->last_rwflags & OPENVPN_VSOCKET_EVENT_READ) && complete_pending_read(sock))
        result |= OPENVPN_VSOCKET_EVENT_READ;
    if ((sock->last_rwflags & OPENVPN_VSOCKET_EVENT_WRITE) &&
        (sock->slot_write.status != IO_SLOT_PENDING || complete_pending_write(sock)))
        result |= OPENVPN_VSOCKET_EVENT_WRITE;

    shapeshifter_obfs4_log(sock->ctx, PLOG_DEBUG, "pump -> %d", result);
    return result;
}

static SSIZE_T shapeshifter_obfs4_win32_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len, struct sockaddr *addr, openvpn_vsocket_socklen_t *addrlen)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    if (!complete_pending_read(sock))
    {
        WSASetLastError(WSA_IO_INCOMPLETE);
        return -1;
    }

    if (!sock->slot_read.succeeded)
    {
        int wsa_error = sock->slot_read.wsa_error;
        consumed_pending_read(sock);
        WSASetLastError(wsa_error);
        return -1;
    }
    
    // sock->slot_read now has valid data.
    char *working_buf = sock->slot_read.buf;
    ssize_t working_len = sock->slot_read.buf_len;

    if (working_len < 0)
    {
        /* Act as though this read never happened. Assume one was queued before, so it should
           still remain queued. */
        consumed_pending_read(sock);
        ensure_pending_read(sock);
        WSASetLastError(WSA_IO_INCOMPLETE);
        return -1;
    }

    size_t copy_len = working_len;
    if (copy_len > len)
        copy_len = len;
    memcpy(buf, sock->slot_read.buf, copy_len);

    /* TODO: shouldn't truncate, should signal error (but this shouldn't happen for any
       supported address families anyway). */
    openvpn_vsocket_socklen_t addr_copy_len = *addrlen;
    if (sock->slot_read.addr_len < addr_copy_len)
        addr_copy_len = sock->slot_read.addr_len;
    memcpy(addr, &sock->slot_read.addr, addr_copy_len);
    *addrlen = addr_copy_len;
//    if (addr_copy_len > 0)
//        shapeshifter_obfs4_munge_addr(addr, addr_copy_len);

    /* Reset the I/O slot before returning. */
    consumed_pending_read(sock);
    return copy_len;
}

static SSIZE_T shapeshifter_obfs4_win32_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len, const struct sockaddr *addr, openvpn_vsocket_socklen_t addrlen)
{
    struct shapeshifter_obfs4_socket_win32 *sock = (struct shapeshifter_obfs4_socket_win32 *)handle;
    complete_pending_write(sock);

    if (sock->slot_write.status == IO_SLOT_PENDING)
    {
        /* This shouldn't really happen, but. */
        WSASetLastError(WSAEWOULDBLOCK);
        return -1;
    }

    if (addrlen > sock->slot_write.addr_cap)
    {
        /* Shouldn't happen. */
        WSASetLastError(WSAEFAULT);
        return -1;
    }

    /* TODO: propagate previous write errors---what does core expect here? */
    memcpy(&sock->slot_write.addr, addr, addrlen);
    sock->slot_write.addr_len = addrlen;
	sock->slot_write.buf_len = len;
    
    queue_new_write(&sock->slot_write);
    switch (sock->slot_write.status)
    {
        case IO_SLOT_PENDING:
            /* The network hasn't given us an error yet, but _we've_ consumed all the bytes.
               ... sort of. */
            return len;

        case IO_SLOT_DORMANT:
            /* Huh?? But we just queued a write. */
            abort();

        case IO_SLOT_COMPLETE:
            if (sock->slot_write.succeeded)
                /* TODO: more partial length handling */
                return len;
            else
                return -1;

        default:
            abort();
    }
}

static void
shapeshifter_obfs4_win32_close(openvpn_vsocket_handle_t handle)
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
