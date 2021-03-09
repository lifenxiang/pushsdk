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

typedef struct registered_data {
    const char *service_type; // "fcm" or "apns"
} registered_data_t;

// registered project id and key on Google Firebase with service type "fcm"
typedef struct registered_project_key {
    const char *service_type; // assigned value with "fcm";
    const char *project_id;
    const char *api_key;
} registered_project_key_t;

// registered certificate and private key on Apple APNs with service type "apns"
typedef struct registered_certificate {
    const char *service_type; // assigned value with "apns";
    const char *certificate_path;
    const char *private_key_path;
} registered_certificate_t;

typedef struct push_server {
    char *host;
    char *port;
} push_server_t;

CARRIER_API
int register_push_service(const push_server_t *push_server,
                          const char *scope,
                          const registered_data_t *data);

CARRIER_API
int unregister_push_service(const push_server_t *push_server,
                            const char *scope,
                            const registered_data_t *data);

typedef struct subscribed_cookie {
    const char *service_type;
} subscribed_cookie_t;

typedef struct subscribed_project_id {
    const char *service_type;
    const char *register_id;
} subscribed_project_id_t;

typedef struct subscribed_devtoken {
    const char *service_type;
    const char *dev_token;
} subscribed_dev_token_t;

CARRIER_API
int subscribe_push_service(const push_server_t *push_server,
                           const char *scope,
                           const char *event_id,
                           const subscribed_cookie_t *cookie);

// device_cookie:
//    ios: device token;
//    android: register id;
CARRIER_API
int unsubscribe_push_service(const push_server_t *push_server,
                             const char *scope,
                             const char *event_id,
                             const subscribed_cookie_t *cookie);

CARRIER_API
int send_push_message(const push_server_t *push_server,
                      const char *scope,
                      const char *event_id,
                      const char *message);

#ifdef __cplusplus
}
#endif

#endif // __PUSH_H__
