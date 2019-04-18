#define _WINSOCKAPI_    // stops windows.h including winsock.h

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "openvpn/openvpn-plugin.h"
#include "openvpn/openvpn-vsocket.h"
#include "shapeshifter-obfs4-server-go.h"
#include "shapeshifter-obfs4.h"

struct openvpn_vsocket_vtab shapeshifter_obfs4_socket_vtab = { NULL };

static void
free_context(struct shapeshifter_obfs4_context *context)
{
    if (!context)
        return;
    free(context);
}

void
shapeshifter_obfs4_log(struct shapeshifter_obfs4_context *ctx, openvpn_plugin_log_flags_t flags, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    ctx->global_vtab->plugin_vlog(flags, shapeshifter_obfs4_PLUGIN_NAME, fmt, va);
    va_end(va);
}

// OpenVPN Plugin API

OPENVPN_EXPORT int openvpn_plugin_open_v3(int version, struct openvpn_plugin_args_open_in const *args, struct openvpn_plugin_args_open_return *out)
{
    // TODO: Documentation for config file
    
    // This is just setting up the context
    // Currently context only does logging to OpenVPN
    struct shapeshifter_obfs4_context *context;
    context = (struct shapeshifter_obfs4_context *) calloc(1, sizeof(struct shapeshifter_obfs4_context));
    context->state_dir = (char *)args->argv[1];
    
    if (!context)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    context->global_vtab = args->callbacks;
    
    // Sets up the VTable, useful stuff
    shapeshifter_obfs4_initialize_socket_vtab();

    // Tells openVPN what events we want the plugin to handle
    out->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_SOCKET_INTERCEPT);
    
    // Gives OpenVPN the handle object to save and later give back to us in other calls
    out->handle = (openvpn_plugin_handle_t *) context;
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    free_context((struct shapeshifter_obfs4_context *) handle);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(int version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr)
{
    /* We don't ask for any bits that use this interface. */
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

// Provides OpenVPN with the VTable
// Functions on the VTable are called when there are network events
OPENVPN_EXPORT void *
openvpn_plugin_get_vtab_v1(int selector, size_t *size_out)
{
    switch (selector)
    {
        case OPENVPN_VTAB_SOCKET_INTERCEPT_SOCKET_V1:
            if (shapeshifter_obfs4_socket_vtab.bind == NULL)
                return NULL;
            *size_out = sizeof(struct openvpn_vsocket_vtab);
            return &shapeshifter_obfs4_socket_vtab;

        default:
            return NULL;
    }
}
