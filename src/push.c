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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "push.h"
#include "http_client.h"

typedef struct key_value {
    const char *key;
    const char *val;
} key_value_t;

static char *encode_x_www_form_urlencoded(http_client_t *httpc, key_value_t kvs[], size_t sz, int *len)
{
    assert(httpc);
    assert(kvs);
    assert(sz);
    assert(len);

    char **vals_encoded = alloca(sizeof(vals_encoded[0]) * sz);
    char *encoded;
    int __len;
    int i;

    for (i = 0, __len = 0; i < sz; ++i) {
        assert(kvs[i].key && *kvs[i].key);
        assert(kvs[i].val && *kvs[i].val);
        vals_encoded[i] = http_client_escape(httpc, kvs[i].val, strlen(kvs[i].val));
        assert(vals_encoded[i]);
        __len += (i ? 2 : 1) + strlen(kvs[i].key) + strlen(vals_encoded[i]);
    }

    encoded = malloc(__len + 1);
    assert(encoded);
    *len = __len;

    for (i = 0, __len = 0; i < sz; ++i) {
        __len += i ? sprintf(encoded + __len, "&%s=%s", kvs[i].key, vals_encoded[i]) :
                     sprintf(encoded + __len, "%s=%s", kvs[i].key, vals_encoded[i]);
        free(vals_encoded[i]);
    }

    return encoded;
}

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
static char *encode_project_key_to_x_www_form_urlencoded(const registered_data_t *data,
                                                         http_client_t *httpc, int *len)
{
    const registered_project_key_t *key = (const registered_project_key_t *)data;

    assert(data);
    assert(httpc);
    assert(len);

    key_value_t kvs[] = {
        {.key = "service"        , .val = key->base.scope},
        {.key = "pushservicetype", .val = "fcm"          },
        {.key = "projectid"      , .val = key->project_id},
        {.key = "apikey"         , .val = key->api_key   }
    };

    return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
}

const registered_data_t *registered_project_key_init(registered_project_key_t *data,
                                                     const char *scope,
                                                     const char *project_id,
                                                     const char *api_key)
{
    if (!data || !scope || !*scope || !project_id || !*project_id || !api_key || !*api_key)
        return NULL;

    data->base.encode_to_x_www_form_urlencoded = encode_project_key_to_x_www_form_urlencoded;
    data->base.scope                           = scope;
    data->project_id                           = project_id;
    data->api_key                              = api_key;

    return &data->base;
}

static char *encode_certificate_to_x_www_form_urlencoded(const registered_data_t *data,
                                                         http_client_t *httpc, int *len)
{
    const registered_certificate_t *cert = (const registered_certificate_t *)data;

    assert(data);
    assert(httpc);
    assert(len);

    key_value_t kvs[] = {
        {.key = "service"        , .val = cert->base.scope      },
        {.key = "pushservicetype", .val = "apns"                },
        {.key = "cert"           , .val = cert->certificate_path},
        {.key = "key"            , .val = cert->private_key_path},
        {.key = "sandbox"        , .val = "true"                }
    };

    return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
}

const registered_data_t *registered_certificate_init(registered_certificate_t *data,
                                                     const char *scope,
                                                     const char *certificate_path,
                                                     const char *private_key_path)
{
    if (!data || !scope || !*scope || !certificate_path || !*certificate_path ||
        !private_key_path || !*private_key_path)
        return NULL;

    data->base.encode_to_x_www_form_urlencoded = encode_certificate_to_x_www_form_urlencoded;
    data->base.scope                           = scope;
    data->certificate_path                     = certificate_path;
    data->private_key_path                     = private_key_path;

    return &data->base;
}

int register_push_service(const push_server_t *push_server,
                          const registered_data_t *data)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host ||
        !push_server->port || !*push_server->port || !data)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = data->encode_to_x_www_form_urlencoded(data, http_client, &body_len);
    if (!body) {
        http_client_close(http_client);
        return -1;
    }

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, push_server->host) ||
        http_client_set_port(http_client, push_server->port) ||
        http_client_set_path(http_client, "/addpsp") ||
        http_client_set_header(http_client, "Content-Type",
                               "application/x-www-form-urlencoded") ||
        http_client_set_request_body_instant(http_client, body, body_len)) {
        http_client_close(http_client);
        free(body);
        return -1;
    }

    rc = http_client_request(http_client);
    free(body);
    if (rc) {
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_get_response_code(http_client, &resp_stat);
    http_client_close(http_client);
    if (rc)
        return -1;

    return (int)resp_stat;
}

int unregister_push_service(const push_server_t *push_server,
                            const registered_data_t *data)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !data)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = data->encode_to_x_www_form_urlencoded(data, http_client, &body_len);
    if (!body) {
        http_client_close(http_client);
        return -1;
    }

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, push_server->host) ||
        http_client_set_port(http_client, push_server->port) ||
        http_client_set_path(http_client, "/rmpsp") ||
        http_client_set_header(http_client, "Content-Type",
                               "application/x-www-form-urlencoded") ||
        http_client_set_request_body_instant(http_client, body, body_len)) {
        free(body);
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_request(http_client);
    free(body);
    if (rc) {
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_get_response_code(http_client, &resp_stat);
    http_client_close(http_client);
    if (rc)
        return -1;

    return (int)resp_stat;
}

static char *encode_fcm_subscriber_to_x_www_form_urlencoded(const subscriber_t *subscriber,
                                                            http_client_t *httpc, int *len)
{
    const fcm_subscriber_t *fcm = (const fcm_subscriber_t *)subscriber;

    assert(subscriber);
    assert(httpc);
    assert(len);

    key_value_t kvs[] = {
        {.key = "service"        , .val = fcm->base.scope   },
        {.key = "subscriber"     , .val = fcm->base.event_id},
        {.key = "pushservicetype", .val = "fcm"             },
        {.key = "regid"          , .val = fcm->register_id  }
    };

    return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
}

const subscriber_t *fcm_subscriber_init(fcm_subscriber_t *subscriber,
                                        const char *scope,
                                        const char *event_id,
                                        const char *register_id)
{
    if (!subscriber || !scope || !*scope || !event_id || !*event_id || !register_id || !*register_id)
        return NULL;

    subscriber->base.encode_to_x_www_form_urlencoded = encode_fcm_subscriber_to_x_www_form_urlencoded;
    subscriber->base.scope                           = scope;
    subscriber->base.event_id                        = event_id;
    subscriber->register_id                          = register_id;

    return &subscriber->base;
}

static char *encode_apns_subscriber_to_x_www_form_urlencoded(const subscriber_t *subscriber,
                                                            http_client_t *httpc, int *len)
{
    const apns_subscriber_t *apns = (const apns_subscriber_t *)subscriber;

    assert(subscriber);
    assert(httpc);
    assert(len);

    key_value_t kvs[] = {
        {.key = "service"        , .val = apns->base.scope   },
        {.key = "subscriber"     , .val = apns->base.event_id},
        {.key = "pushservicetype", .val = "apns"             },
        {.key = "devtoken"       , .val = apns->device_token }
    };

    return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
}

const subscriber_t *apns_subscriber_init(apns_subscriber_t *subscriber,
                                         const char *scope,
                                         const char *event_id,
                                         const char *device_token)
{
    if (!subscriber || !scope || !*scope || !event_id || !*event_id || !device_token || !*device_token)
        return NULL;

    subscriber->base.encode_to_x_www_form_urlencoded = encode_apns_subscriber_to_x_www_form_urlencoded;
    subscriber->base.scope                           = scope;
    subscriber->base.event_id                        = event_id;
    subscriber->device_token                         = device_token;

    return &subscriber->base;
}

int subscribe_push_service(const push_server_t *push_server,
                           const subscriber_t *subscriber)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !subscriber)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = subscriber->encode_to_x_www_form_urlencoded(subscriber, http_client, &body_len);
    if (!body) {
        http_client_close(http_client);
        return -1;
    }

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, push_server->host) ||
        http_client_set_port(http_client, push_server->port) ||
        http_client_set_path(http_client, "/subscribe") ||
        http_client_set_header(http_client, "Content-Type",
                               "application/x-www-form-urlencoded") ||
        http_client_set_request_body_instant(http_client, body, body_len)) {
        free(body);
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_request(http_client);
    free(body);
    if (rc) {
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_get_response_code(http_client, &resp_stat);
    http_client_close(http_client);
    if (rc)
        return -1;

    return (int)resp_stat;
}

int unsubscribe_push_service(const push_server_t *push_server,
                             const subscriber_t *subscriber)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !subscriber)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = subscriber->encode_to_x_www_form_urlencoded(subscriber, http_client, &body_len);
    if (!body) {
        http_client_close(http_client);
        return -1;
    }

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, push_server->host) ||
        http_client_set_port(http_client, push_server->port) ||
        http_client_set_path(http_client, "/unsubscribe") ||
        http_client_set_header(http_client, "Content-Type",
                               "application/x-www-form-urlencoded") ||
        http_client_set_request_body_instant(http_client, body, body_len)) {
        free(body);
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_request(http_client);
    free(body);
    if (rc) {
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_get_response_code(http_client, &resp_stat);
    http_client_close(http_client);
    if (rc)
        return -1;

    return (int)resp_stat;
}

static char *encode_message_to_x_www_form_urlencoded(const message_t *message,
                                                     http_client_t *httpc, int *len)
{
    assert(message);
    assert(httpc);
    assert(len);

    key_value_t kvs[] = {
        {.key = "service"   , .val = message->scope   },
        {.key = "subscriber", .val = message->event_id},
        {.key = "msg"       , .val = message->message }
    };

    return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
}

const message_t *message_init(message_t *message, const char *scope,
                              const char *event_id, const char *content)
{
    if (!message || !scope || !*scope || !event_id || !*event_id || !content || !*content)
        return NULL;

    message->scope                           = scope;
    message->event_id                        = event_id;
    message->message                         = content;
    message->encode_to_x_www_form_urlencoded = encode_message_to_x_www_form_urlencoded;

    return message;
}

int send_push_message(const push_server_t *push_server,
                      const message_t *message)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !message)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = message->encode_to_x_www_form_urlencoded(message, http_client, &body_len);
    if (!body) {
        http_client_close(http_client);
        return -1;
    }

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, push_server->host) ||
        http_client_set_port(http_client, push_server->port) ||
        http_client_set_path(http_client, "/push") ||
        http_client_set_header(http_client, "Content-Type",
                               "application/x-www-form-urlencoded") ||
        http_client_set_request_body_instant(http_client, body, body_len)) {
        free(body);
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_request(http_client);
    free(body);
    if (rc) {
        http_client_close(http_client);
        return -1;
    }

    rc = http_client_get_response_code(http_client, &resp_stat);
    http_client_close(http_client);
    if (rc)
        return -1;

    return (int)resp_stat;
}
