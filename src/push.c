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
#include <stdbool.h>

#include "push.h"
#include "http_client.h"

typedef struct {
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

static bool registered_data_is_valid(const registered_data_t *data)
{
    assert(data);

    union {
        registered_data_t *base;
        registered_project_key_t *project_key;
        registered_certificate_t *certificate;
    } __data = {
        .base = data
    };

    if (!strcmp(__data.base->service_type, "fcm"))
        return __data.project_key->api_key && *__data.project_key->api_key &&
               __data.project_key->project_id && *__data.project_key->project_id;
    else if (!strcmp(__data.base->service_type, "apns"))
        return __data.certificate->certificate_path && *__data.certificate->certificate_path &&
               __data.certificate->private_key_path && *__data.certificate->private_key_path;
    else
        return false;
}

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
static char *encode_register_push_service_body(http_client_t *httpc, const char *scope,
                                               const registered_data_t *data, int *len)
{
    assert(httpc);
    assert(scope);
    assert(data);
    assert(len);

    union {
        registered_data_t *base;
        registered_project_key_t *project_key;
        registered_certificate_t *certificate;
    } __data = {
        .base = data
    };

    if (!strcmp(__data.base->service_type, "fcm")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                               },
            {.key = "pushservicetype", .val = "fcm"                               },
            {.key = "projectid"      , .val = __data.project_key->project_id      },
            {.key = "apikey"         , .val = __data.project_key->api_key         }
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else if (!strcmp(__data.base->service_type, "apns")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                               },
            {.key = "pushservicetype", .val = "apns"                              },
            {.key = "cert"           , .val = __data.certificate->certificate_path},
            {.key = "key"            , .val = __data.certificate->private_key_path},
            {.key = "sandbox"        , .val = "true"                              }
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else
        assert(0);
}

int register_push_service(const push_server_t *push_server,
                          const char *scope,
                          const registered_data_t *data)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host ||
        !push_server->port || !*push_server->port || !scope || !*scope ||
        !data || !registered_data_is_valid(data))
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = encode_register_push_service_body(http_client, scope, data, &body_len);
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

static char *encode_unregister_push_service_body(http_client_t *httpc, const char *scope,
                                               const registered_data_t *data, int *len)
{
    assert(httpc);
    assert(scope);
    assert(data);
    assert(len);

    union {
        registered_data_t *base;
        registered_project_key_t *project_key;
        registered_certificate_t *certificate;
    } __data = {
        .base = data
    };

    if (!strcmp(__data.base->service_type, "fcm")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                               },
            {.key = "pushservicetype", .val = "fcm"                               },
            {.key = "projectid"      , .val = __data.project_key->project_id      },
            {.key = "apikey"         , .val = __data.project_key->api_key         }
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else if (!strcmp(__data.base->service_type, "apns")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                               },
            {.key = "pushservicetype", .val = "apns"                              },
            {.key = "cert"           , .val = __data.certificate->certificate_path},
            {.key = "key"            , .val = __data.certificate->private_key_path},
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else
        assert(0);
}

int unregister_push_service(const push_server_t *push_server,
                            const char *scope,
                            const registered_data_t *data)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !scope || !*scope || !data || !registered_data_is_valid(data))
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = encode_unregister_push_service_body(http_client, scope, data, &body_len);
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

static bool subscribed_cookie_is_valid(const subscribed_cookie_t *cookie)
{
    assert(cookie);

    union {
        const subscribed_cookie_t *base;
        const subscribed_project_id_t *project_id;
        const subscribed_dev_token_t *dev_token;
    } __cookie = {
        .base = cookie
    };

    if (!strcmp(__cookie.base->service_type, "fcm"))
        return __cookie.project_id->register_id && *__cookie.project_id->register_id;
    else if (!strcmp(__cookie.base->service_type, "apns"))
        return __cookie.dev_token->dev_token && *__cookie.dev_token->dev_token;
    else
        return false;
}

static char *encode_subscribe_push_service_body(http_client_t *httpc, const char *scope,
                                                const char *event_id,
                                                const subscribed_cookie_t *cookie, int *len)
{
    assert(httpc);
    assert(scope);
    assert(event_id);
    assert(cookie);

    union {
        const subscribed_cookie_t *base;
        const subscribed_project_id_t *project_id;
        const subscribed_dev_token_t *dev_token;
    } __cookie = {
        .base = cookie
    };

    if (!strcmp(__cookie.base->service_type, "fcm")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                           },
            {.key = "subscriber"     , .val = event_id                        },
            {.key = "pushservicetype", .val = "fcm"                           },
            {.key = "regid"          , .val = __cookie.project_id->register_id}
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else if (!strcmp(__cookie.base->service_type, "apns")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                           },
            {.key = "subscriber"     , .val = event_id                        },
            {.key = "pushservicetype", .val = "apns"                          },
            {.key = "devtoken"       , .val = __cookie.dev_token->dev_token   }
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else
        assert(0);
}

int subscribe_push_service(const push_server_t *push_server,
                           const char *scope,
                           const char *event_id,
                           const subscribed_cookie_t *cookie)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !scope || !*scope || !event_id || !*event_id || !cookie ||
        !subscribed_cookie_is_valid(cookie))
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = encode_subscribe_push_service_body(http_client, scope, event_id, cookie, &body_len);
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

static char *encode_unsubscribe_push_service_body(http_client_t *httpc, const char *scope,
                                                const char *event_id,
                                                const subscribed_cookie_t *cookie, int *len)
{
    assert(httpc);
    assert(scope);
    assert(event_id);
    assert(cookie);

    union {
        const subscribed_cookie_t *base;
        const subscribed_project_id_t *project_id;
        const subscribed_dev_token_t *dev_token;
    } __cookie = {
        .base = cookie
    };

    if (!strcmp(__cookie.base->service_type, "fcm")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                           },
            {.key = "subscriber"     , .val = event_id                        },
            {.key = "pushservicetype", .val = "fcm"                           },
            {.key = "regid"          , .val = __cookie.project_id->register_id}
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else if (!strcmp(__cookie.base->service_type, "apns")) {
        key_value_t kvs[] = {
            {.key = "service"        , .val = scope                           },
            {.key = "subscriber"     , .val = event_id                        },
            {.key = "pushservicetype", .val = "apns"                          },
            {.key = "devtoken"       , .val = __cookie.dev_token->dev_token   }
        };
        return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
    } else
        assert(0);
}

int unsubscribe_push_service(const push_server_t *push_server,
                             const char *scope,
                             const char *event_id,
                             const subscribed_cookie_t *cookie)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !scope || !*scope || !event_id || !*event_id || !cookie ||
        !subscribed_cookie_is_valid(cookie))
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = encode_unsubscribe_push_service_body(http_client, scope, event_id, cookie, &body_len);
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

static char *encode_send_push_message_body(http_client_t *httpc, const char *scope,
                                           const char *event_id, const char *message, int *len)
{
    assert(httpc);
    assert(scope);
    assert(event_id);
    assert(message);
    assert(len);

    key_value_t kvs[] = {
        {.key = "service"   , .val = scope   },
        {.key = "subscriber", .val = event_id},
        {.key = "msg"       , .val = message }
    };

    return encode_x_www_form_urlencoded(httpc, kvs, ARRAY_SIZE(kvs), len);
}

int send_push_message(const push_server_t *push_server, const char *scope,
                      const char *event_id, const char *message)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    int body_len;
    int rc;

    if (!push_server || !push_server->host || !*push_server->host || !push_server->port ||
        !*push_server->port || !scope || !*scope || !event_id || !*event_id || !message || !*message)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    body = encode_send_push_message_body(http_client, scope, event_id, message, &body_len);
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