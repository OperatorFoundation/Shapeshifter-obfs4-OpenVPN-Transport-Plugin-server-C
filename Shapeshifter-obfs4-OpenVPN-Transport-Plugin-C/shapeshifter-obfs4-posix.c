#include "shapeshifter-obfs4.h"
#include "Shapeshifter-obfs4-OpenVPN-Transport-Plugin.h"
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct shapeshifter_obfs4_socket_posix
{
    struct openvpn_vsocket_handle handle;
    struct shapeshifter_obfs4_context *ctx;
    GoInt client_id;
    int pipe_fd[2];
    unsigned last_rwflags;
};

static void
free_socket(struct shapeshifter_obfs4_socket_posix *sock)
{
    if (!sock)
        return;
    
    Obfs4_close_connection(sock->client_id);
    close(sock->pipe_fd[0]);
    close(sock->pipe_fd[1]);
    
    free(sock);
}

static openvpn_vsocket_handle_t shapeshifter_obfs4_posix_bind(void *plugin_handle,
                                                              const struct sockaddr *addr,
                                                              socklen_t len)
{
    struct shapeshifter_obfs4_socket_posix *sock = NULL;

    sock = calloc(1, sizeof(struct shapeshifter_obfs4_socket_posix));
    if (!sock)
        goto error;
    
    pipe(sock->pipe_fd);
    sock->handle.vtab = &shapeshifter_obfs4_socket_vtab;
    sock->ctx = (struct shapeshifter_obfs4_context *) plugin_handle;

    // Create an obfs4 client.
    sock->client_id = Initialize_obfs4_c_client(sock->ctx->cert_string, sock->ctx->iat_mode);
    
    //FIXME: This only works for ipv4 addresses, need to address ipv6
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    GoInt dial_result = Obfs4_dial(sock->client_id, inet_ntoa(addr_in->sin_addr));
    
    if (dial_result != 0)
        goto error;
    
    return &sock->handle;

error:
    free_socket(sock);
    return NULL;
}

// What OpenVPN is requesting to be notified of
static void
shapeshifter_obfs4_posix_request_event(openvpn_vsocket_handle_t handle,
                              openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "request-event: %d", rwflags);
    ((struct shapeshifter_obfs4_socket_posix *) handle)->last_rwflags = 0;
    
    if (rwflags) {
        event_set->vtab->set_event(event_set, ((struct shapeshifter_obfs4_socket_posix *) handle)->pipe_fd[0], rwflags, handle);
    }
}

// Tell us whether the underlying file descriptor is ready for R/W
static bool
shapeshifter_obfs4_posix_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "update-event: %p, %p, %d", handle, arg, rwflags);
    
    if (arg != handle) {
        return false;
    }
    
    ((struct shapeshifter_obfs4_socket_posix *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned
shapeshifter_obfs4_posix_pump(openvpn_vsocket_handle_t handle)
{
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "pump -> %d", ((struct shapeshifter_obfs4_socket_posix *) handle)->last_rwflags);
    
    return ((struct shapeshifter_obfs4_socket_posix *) handle)->last_rwflags;
}

// Receive Data from the other side
static ssize_t
shapeshifter_obfs4_posix_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len,
                         struct sockaddr *addr, socklen_t *addrlen)
{
    
    GoInt client_id = ((struct shapeshifter_obfs4_socket_posix *) handle)->client_id;
    GoInt number_of_bytes_read = Obfs4_read(client_id, (void *)buf, (int)len);

    // If we receive "there is no data available right now, try again later"
    // Set a flag saying we are not ready to try again
    if (number_of_bytes_read < 0)
    {
        return -1;
    }

    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "recvfrom(%d) -> %d", (int)len, (int)number_of_bytes_read);
    
    return number_of_bytes_read;
}

// Send data to the other side
static ssize_t
shapeshifter_obfs4_posix_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len,
                       const struct sockaddr *addr, socklen_t addrlen)
{
    GoInt client_id = ((struct shapeshifter_obfs4_socket_posix *) handle)->client_id;
    GoInt number_of_characters_sent = Obfs4_write(client_id, (void *)buf, (int)len);
    
    if (number_of_characters_sent < 0)
    {
        goto error;
    }
    
    shapeshifter_obfs4_log(((struct shapeshifter_obfs4_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "sendto(%d) -> %d", (int)len, (int)number_of_characters_sent);

    return number_of_characters_sent;

error:
    return -1;
}

static void
shapeshifter_obfs4_posix_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct shapeshifter_obfs4_socket_posix *) handle);
}

// All of the functions that should be called by OpenVPN when an event happens
void
shapeshifter_obfs4_initialize_socket_vtab(void)
{
    shapeshifter_obfs4_socket_vtab.bind = shapeshifter_obfs4_posix_bind;
    shapeshifter_obfs4_socket_vtab.request_event = shapeshifter_obfs4_posix_request_event;
    shapeshifter_obfs4_socket_vtab.update_event = shapeshifter_obfs4_posix_update_event;
    shapeshifter_obfs4_socket_vtab.pump = shapeshifter_obfs4_posix_pump;
    shapeshifter_obfs4_socket_vtab.recvfrom = shapeshifter_obfs4_posix_recvfrom;
    shapeshifter_obfs4_socket_vtab.sendto = shapeshifter_obfs4_posix_sendto;
    shapeshifter_obfs4_socket_vtab.close = shapeshifter_obfs4_posix_close;
}
