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

typedef struct PushServer {
    char *host;
    char *port;
} PushServer;

CARRIER_API
int subscribe(const PushServer *server, const char *scope,
              const char *subscriber, const char *push_service_type,
              const char *reg_id_or_dev_token);

CARRIER_API
int unsubscribe(const PushServer *server, const char *scope,
                const char *subscriber, const char *push_service_type,
                const char *reg_id_or_dev_token);

CARRIER_API
int add_push_service_provider(const PushServer *server, const char *scope,
                              const char *push_service_type, const char *project_id_or_cert_path,
                              const char *api_key_or_sk_path);

CARRIER_API
int remove_push_service_provider(const PushServer *server, const char *scope,
                                 const char *push_service_type, const char *project_id_or_cert_path,
                                 const char *api_key_or_sk_path);

CARRIER_API
int send_push(const PushServer *server, const char *scope, const char *subscriber, const char *message);

#ifdef __cplusplus
}
#endif

#endif // __PUSH_H__
