#ifndef OPENVPN_VSOCKET_H_
#define OPENVPN_VSOCKET_H_

/* PLATFORM: only POSIX-y platforms or Win32 here */

#ifdef _WIN32

/* Win32 */
#define OPENVPN_VSOCKET_PLATFORM_WIN32
#include <stdbool.h>
#include <windows.h>
#include <winsock2.h>

/* On Windows, platform-native events to wait on are provided to OpenVPN core as
   pairs of system events, normally corresponding to one potentially queued I/O
   operation in each direction. The read event is waited on if read events are
   requested, and the write event is waited on if write events are
   requested. Events need not be distinct, but usually will be. Two event
   handles must always be provided; neither is permitted to be NULL. */
typedef const struct openvpn_vsocket_win32_event_pair {
    HANDLE read;
    HANDLE write;
} *openvpn_vsocket_native_event_t;

/* Windows doesn't have socklen_t; it uses int. */
typedef int openvpn_vsocket_socklen_t;
typedef int SSIZE_T ssize_t;

#else

/* POSIX-y */
#define OPENVPN_VSOCKET_PLATFORM_POSIX
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

/* On POSIX-y platforms, platform-native events to wait on are provided to
   OpenVPN core as file descriptors.  Readiness for read and write are defined
   the same way as in poll, epoll, and similar system APIs. The file descriptor
   may be of any type which can be waited on. */
typedef int openvpn_vsocket_native_event_t;

/* Alias natural socklen_t definition. */
typedef socklen_t openvpn_vsocket_socklen_t;

#endif

/* rwflags values are a bitwise OR of zero or more of these values, indicating
   what types of events are being requested or returned for a given object. */
#define OPENVPN_VSOCKET_EVENT_READ  (1<<0)
#define OPENVPN_VSOCKET_EVENT_WRITE (1<<1)

/* Handle to an object that can accumulate requests to wait on platform-native
   event sources. Use the functions in the vtable to operate on it. */
typedef struct openvpn_vsocket_event_set_handle *openvpn_vsocket_event_set_handle_t;

struct openvpn_vsocket_event_set_vtab {
    /* Request to be notified when ev becomes ready in any of the ways specified
       by the bitmask rwflags. Incoming notifications will have arg passed
       through as-is. See above for the definition of native events on different
       platforms.

       Note that arg must be a distinct, owned pointer and not NULL; see
       update_event below. */
    void (*set_event)(openvpn_vsocket_event_set_handle_t handle,
                      openvpn_vsocket_native_event_t ev, unsigned rwflags,
                      void *arg);
};

/* Implementation extends this structure with state. Implementation is normally
   provided by OpenVPN core; see request_event in struct
   openvpn_vsocket_vtab. */
struct openvpn_vsocket_event_set_handle {
    const struct openvpn_vsocket_event_set_vtab *vtab;
};

/* Handle to a virtual datagram socket, non-connection-oriented. */
typedef struct openvpn_vsocket_handle *openvpn_vsocket_handle_t;

/* Implementation extends this structure with state. Implementation is normally
   provided by a plugin providing an indirect socket mechanism. */
struct openvpn_vsocket_handle {
    const struct openvpn_vsocket_vtab *vtab;
};

/* Virtual socket implementations should expect (and consumers must
   provide) vtable calls in the following order:

     - bind must occur first.
     - request_event is followed by zero or more update_event calls, and then a
       pump call, before any further request_event calls occur.
     - recvfrom/sendto may occur at any time between bind and close, including
       interleaved with the event request cycle above.
     - close must occur last.

   Error reporting is platform-native: errno on POSIX-y systems, or
   Winsock errors on Windows systems.
 */

struct openvpn_vsocket_vtab {
    /* Bind a new virtual socket to addr/len. addr must not be NULL.
       plugin_handle is actually of type openvpn_plugin_handle_t. */
    openvpn_vsocket_handle_t (*bind)(void *plugin_handle,
                                     const struct sockaddr *addr,
                                     openvpn_vsocket_socklen_t len);

    /* Given the bitmask rwflags, request that event_set be provided with all
       native events that should be waited on such that whenever this virtual
       socket may become ready in a way specified by rwflags, one of the
       native events will become ready. This function should call

         event_set->vtab->set_event(event_set, ...)

       zero or more times for this purpose.

       The state of event_set should be assumed not to persist between calls to
       request_event; every native event must be provided every time. Currently,
       only one native event may be supplied (i.e., one call above). */
    void (*request_event)(openvpn_vsocket_handle_t handle,
                          openvpn_vsocket_event_set_handle_t event_set,
                          unsigned rwflags);

    /* Indicate to the virtual socket that a native event for which arg was
       provided to a set_event call above became ready in a manner indicated by
       the bitmask rwflags.  This function _must_ test for whether arg
       corresponds to an actual requested event from this virtual socket.

       If arg corresponds to a requested event, update_event does any necessary
       internal state updates and _returns true_ to consume the event.

       If arg does not correspond to a requested event, update_event
       does nothing and _returns false_. */
    bool (*update_event)(openvpn_vsocket_handle_t handle, void *arg,
                         unsigned rwflags);

    /* Perform any pending processing that can be performed immediately, and
       return a bitmask indicating whether this virtual socket is ready to
       receive/send more packets. */
    unsigned (*pump)(openvpn_vsocket_handle_t handle);

    /* Receive a packet into buf/len, storing the address into addr/ *addrlen and
       updating *addrlen to match. Returns -1 on error, or the number of bytes
       received. Must not block; signals an error if there is nothing to
       receive. */
    ssize_t (*recvfrom)(openvpn_vsocket_handle_t handle,
                        void *buf, size_t len,
                        struct sockaddr *addr,
                        openvpn_vsocket_socklen_t *addrlen);

    /* Send a packet from buf/len to the address addr/addrlen. Returns -1 on
       error, or the number of bytes sent. Must not block; signals an error if
       there is no room to send. */
    ssize_t (*sendto)(openvpn_vsocket_handle_t handle,
                      const void *buf, size_t len,
                      const struct sockaddr *addr,
                      openvpn_vsocket_socklen_t addrlen);

    /* Destroy this virtual socket and free all resources allocated for it. The
       virtual socket must not be used afterward. */
    void (*close)(openvpn_vsocket_handle_t handle);
};

#endif
