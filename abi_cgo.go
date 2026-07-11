//go:build cgo

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct cliproxy_buffer {
    void*  ptr;
    size_t len;
} cliproxy_buffer;

typedef int  (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct cliproxy_plugin_api {
    uint32_t                abi_version;
    cliproxy_plugin_call_fn      call;
    cliproxy_plugin_free_fn      free_buffer;
    cliproxy_plugin_shutdown_fn  shutdown;
} cliproxy_plugin_api;

typedef struct cliproxy_host_api {
    uint32_t abi_version;
    void*    host_ctx;
    void*    call;
    void*    free_buffer;
} cliproxy_host_api;

extern int  cliproxyPluginCall(char* method, uint8_t* request, size_t request_len, cliproxy_buffer* response);
extern void cliproxyPluginFree(void* ptr, size_t len);
extern void cliproxyPluginShutdown();
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	_ = host
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (ret C.int) {
	defer func() {
		if r := recover(); r != nil {
			if response != nil {
				response.ptr = nil
				response.len = 0
				writeResponse(response, errorEnvelope("plugin_panic", fmt.Sprintf("%v", r)))
			}
			ret = 1
		}
	}()

	if response != nil {
		response.ptr = nil
		response.len = 0
	}

	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}

	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}

	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	pluginShutdown()
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
