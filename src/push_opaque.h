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

#ifndef __PUSH_OPAQUE_H__
#define __PUSH_OPAQUE_H__

typedef struct http_client http_client_t;

typedef struct registered_data registered_data_t;
struct registered_data {
    const char *scope;
    char *(*encode_to_x_www_form_urlencoded)(const registered_data_t *, http_client_t *, int *);
};

typedef struct registered_project_key {
    registered_data_t base;
    const char *project_id;
    const char *api_key;
} registered_project_key_t;

typedef struct registered_certificate {
    registered_data_t base;
    const char *certificate_path;
    const char *private_key_path;
} registered_certificate_t;

typedef struct subscriber subscriber_t;
struct subscriber {
    const char *scope;
    const char *event_id;
    char *(*encode_to_x_www_form_urlencoded)(const subscriber_t *, http_client_t *, int *);
};

typedef struct fcm_subscriber {
    subscriber_t base;
    const char *register_id;
} fcm_subscriber_t;

typedef struct apns_subscriber {
    subscriber_t base;
    const char *device_token;
} apns_subscriber_t;

typedef struct message message_t;
struct message {
    const char *scope;
    const char *event_id;
    const char *message;
    char *(*encode_to_x_www_form_urlencoded)(const message_t *, http_client_t *, int *);
};

#endif // __PUSH_OPAQUE_H__
