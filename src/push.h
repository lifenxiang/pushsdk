/*
 * Copyright (c) 2021 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __PUSH_H__
#define __PUSH_H__

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CARRIER_STATIC)
  #define CARRIER_API
#elif defined(CARRIER_DYNAMIC)
  #ifdef CARRIER_BUILD
    #if defined(_WIN32) || defined(_WIN64)
      #define CARRIER_API        __declspec(dllexport)
    #else
      #define CARRIER_API        __attribute__((visibility("default")))
    #endif
  #else
    #if defined(_WIN32) || defined(_WIN64)
      #define CARRIER_API        __declspec(dllimport)
    #else
      #define CARRIER_API        __attribute__((visibility("default")))
    #endif
  #endif
#else
  #define CARRIER_API
#endif

#ifdef CARRIER_BUILD
    #include "push_opaque.h"
#else
    #include <push_opaque.h>
#endif

typedef struct registered_data registered_data_t;
typedef struct registered_project_key registered_project_key_t;
typedef struct registered_certificate registered_certificate_t;

typedef struct subscriber subscriber_t;
typedef struct fcm_subscriber fcm_subscriber_t;
typedef struct apns_subscriber apns_subscriber_t;

typedef struct message message_t;

typedef struct push_server {
    char *host;
    char *port;
} push_server_t;

CARRIER_API
const registered_data_t *registered_project_key_init(registered_project_key_t *data,
                                                     const char *scope,
                                                     const char *project_id,
                                                     const char *api_key);

CARRIER_API
const registered_data_t *registered_certificate_init(registered_certificate_t *data,
                                                     const char *scope,
                                                     const char *certificate_path,
                                                     const char *private_key_path);

CARRIER_API
int register_push_service(const push_server_t *push_server,
                          const registered_data_t *data);

CARRIER_API
int unregister_push_service(const push_server_t *push_server,
                            const registered_data_t *data);

CARRIER_API
const subscriber_t *fcm_subscriber_init(fcm_subscriber_t *subscriber,
                                        const char *scope,
                                        const char *event_id,
                                        const char *register_id);

CARRIER_API
const subscriber_t *apns_subscriber_init(apns_subscriber_t *subscriber,
                                         const char *scope,
                                         const char *event_id,
                                         const char *device_token);

CARRIER_API
int subscribe_push_service(const push_server_t *push_server,
                           const subscriber_t *subscriber);
CARRIER_API
int unsubscribe_push_service(const push_server_t *push_server,
                             const subscriber_t *subscriber);

CARRIER_API
const message_t *message_init(message_t *message,
                              const char *scope,
                              const char *event_id,
                              const char *content);

CARRIER_API
int send_push_message(const push_server_t *push_server,
                      const message_t *message);

#ifdef __cplusplus
}
#endif

#endif // __PUSH_H__
