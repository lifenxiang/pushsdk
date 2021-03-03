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

#include "push.h"
#include "http_client.h"

int subscribe(const PushServer *server, const char *scope,
              const char *subscriber, const char *push_service_type,
              const char *reg_id_or_dev_token)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    char *reg_id_or_dev_token_esc = NULL;
    char *push_svc_type_esc = NULL;
    char *suber_esc = NULL;
    char *svc_esc = NULL;
    int body_len;
    int rc;

    if (!server || !server->host || !*server->host || !server->port ||
        !*server->port || !scope || !*scope || !subscriber || !*subscriber ||
        !push_service_type || !*push_service_type ||
        !reg_id_or_dev_token || !*reg_id_or_dev_token)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    if (!(svc_esc = http_client_escape(http_client, scope, strlen(scope))) ||
        !(suber_esc = http_client_escape(http_client, subscriber, strlen(subscriber))) ||
        !(push_svc_type_esc = http_client_escape(http_client, push_service_type, strlen(push_service_type))) ||
        !(reg_id_or_dev_token_esc = http_client_escape(http_client, reg_id_or_dev_token, strlen(reg_id_or_dev_token)))) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(reg_id_or_dev_token_esc);
        http_client_close(http_client);
        return -1;
    }

    body_len = snprintf(NULL, 0, "service=%s&subscriber=%s&pushservicetype=%s&%s=%s",
                        svc_esc, suber_esc, push_svc_type_esc,
                        !strcmp(push_service_type, "apns") ? "devtoken" : "regid", reg_id_or_dev_token_esc);
    if (body_len <= 0) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(reg_id_or_dev_token_esc);
        http_client_close(http_client);
        return -1;
    }

    body = malloc(body_len + 1);
    if (!body) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(reg_id_or_dev_token_esc);
        http_client_close(http_client);
        return -1;
    }

    snprintf(body, body_len + 1, "service=%s&subscriber=%s&pushservicetype=%s&%s=%s",
             svc_esc, suber_esc, push_svc_type_esc,
             !strcmp(push_service_type, "apns") ? "devtoken" : "regid", reg_id_or_dev_token_esc);
    http_client_memory_free(svc_esc);
    http_client_memory_free(suber_esc);
    http_client_memory_free(push_svc_type_esc);
    http_client_memory_free(reg_id_or_dev_token_esc);

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, server->host) ||
        http_client_set_port(http_client, server->port) ||
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

int unsubscribe(const PushServer *server, const char *scope,
                const char *subscriber, const char *push_service_type,
                const char *reg_id_or_dev_token)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    char *reg_id_or_dev_token_esc = NULL;
    char *push_svc_type_esc = NULL;
    char *suber_esc = NULL;
    char *svc_esc = NULL;
    int body_len;
    int rc;

    if (!server || !server->host || !*server->host || !server->port ||
        !*server->port || !scope || !*scope || !subscriber || !*subscriber ||
        !push_service_type || !*push_service_type ||
        !reg_id_or_dev_token || !*reg_id_or_dev_token)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    if (!(svc_esc = http_client_escape(http_client, scope, strlen(scope))) ||
        !(suber_esc = http_client_escape(http_client, subscriber, strlen(subscriber))) ||
        !(push_svc_type_esc = http_client_escape(http_client, push_service_type, strlen(push_service_type))) ||
        !(reg_id_or_dev_token_esc = http_client_escape(http_client, reg_id_or_dev_token, strlen(reg_id_or_dev_token)))) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(reg_id_or_dev_token_esc);
        http_client_close(http_client);
        return -1;
    }

    body_len = snprintf(NULL, 0, "service=%s&subscriber=%s&pushservicetype=%s&%s=%s",
                        svc_esc, suber_esc, push_svc_type_esc,
                        !strcmp(push_service_type, "apns") ? "devtoken" : "regid", reg_id_or_dev_token_esc);
    if (body_len <= 0) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(reg_id_or_dev_token_esc);
        http_client_close(http_client);
        return -1;
    }

    body = malloc(body_len + 1);
    if (!body) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(reg_id_or_dev_token_esc);
        http_client_close(http_client);
        return -1;
    }

    snprintf(body, body_len + 1, "service=%s&subscriber=%s&pushservicetype=%s&%s=%s",
             svc_esc, suber_esc, push_svc_type_esc,
             !strcmp(push_service_type, "apns") ? "devtoken" : "regid", reg_id_or_dev_token_esc);
    http_client_memory_free(svc_esc);
    http_client_memory_free(suber_esc);
    http_client_memory_free(push_svc_type_esc);
    http_client_memory_free(reg_id_or_dev_token_esc);

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, server->host) ||
        http_client_set_port(http_client, server->port) ||
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

int add_push_service_provider(const PushServer *server, const char *scope,
                              const char *push_service_type, const char *project_id_or_cert_path,
                              const char *api_key_or_sk_path)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    char *prj_id_or_cert_esc = NULL;
    char *api_key_or_sk_esc = NULL;
    char *push_svc_type_esc = NULL;
    char *svc_esc = NULL;
    int body_len;
    int rc;

    if (!server || !server->host || !*server->host || !server->port ||
        !*server->port || !scope || !*scope ||
        !push_service_type || !*push_service_type ||
        !project_id_or_cert_path || !*project_id_or_cert_path ||
        !api_key_or_sk_path || !*api_key_or_sk_path)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    if (!(svc_esc = http_client_escape(http_client, scope, strlen(scope))) ||
        !(push_svc_type_esc = http_client_escape(http_client, push_service_type, strlen(push_service_type))) ||
        !(prj_id_or_cert_esc = http_client_escape(http_client, project_id_or_cert_path, strlen(project_id_or_cert_path))) ||
        !(api_key_or_sk_esc = http_client_escape(http_client, api_key_or_sk_path, strlen(api_key_or_sk_path)))) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(prj_id_or_cert_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(api_key_or_sk_esc);
        http_client_close(http_client);
        return -1;
    }

    body_len = snprintf(NULL, 0, "service=%s&pushservicetype=%s&%s=%s&%s=%s%s",
                        svc_esc, push_svc_type_esc,
                        !strcmp(push_service_type, "apns") ? "cert" : "projectid",
                        prj_id_or_cert_esc,
                        !strcmp(push_service_type, "apns") ? "key" : "apikey",
                        api_key_or_sk_esc,
                        !strcmp(push_service_type, "apns") ? "&sandbox=true" : "");
    if (body_len <= 0) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(prj_id_or_cert_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(api_key_or_sk_esc);
        http_client_close(http_client);
        return -1;
    }

    body = malloc(body_len + 1);
    if (!body) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(prj_id_or_cert_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(api_key_or_sk_esc);
        http_client_close(http_client);
        return -1;
    }

    snprintf(body, body_len + 1, "service=%s&pushservicetype=%s&%s=%s&%s=%s%s",
             svc_esc, push_svc_type_esc,
             !strcmp(push_service_type, "apns") ? "cert" : "projectid",
             prj_id_or_cert_esc,
             !strcmp(push_service_type, "apns") ? "key" : "apikey",
             api_key_or_sk_esc,
             !strcmp(push_service_type, "apns") ? "&sandbox=true" : "");
    http_client_memory_free(svc_esc);
    http_client_memory_free(prj_id_or_cert_esc);
    http_client_memory_free(push_svc_type_esc);
    http_client_memory_free(api_key_or_sk_esc);

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, server->host) ||
        http_client_set_port(http_client, server->port) ||
        http_client_set_path(http_client, "/addpsp") ||
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

int remove_push_service_provider(const PushServer *server, const char *scope,
                                 const char *push_service_type, const char *project_id_or_cert_path,
                                 const char *api_key_or_sk_path)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    char *prj_id_or_cert_esc = NULL;
    char *api_key_or_sk_esc = NULL;
    char *push_svc_type_esc = NULL;
    char *svc_esc = NULL;
    int body_len;
    int rc;

    if (!server || !server->host || !*server->host || !server->port ||
        !*server->port || !scope || !*scope ||
        !push_service_type || !*push_service_type ||
        !project_id_or_cert_path || !*project_id_or_cert_path ||
        !api_key_or_sk_path || !*api_key_or_sk_path)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    if (!(svc_esc = http_client_escape(http_client, scope, strlen(scope))) ||
        !(push_svc_type_esc = http_client_escape(http_client, push_service_type, strlen(push_service_type))) ||
        !(prj_id_or_cert_esc = http_client_escape(http_client, project_id_or_cert_path, strlen(project_id_or_cert_path))) ||
        !(api_key_or_sk_esc = http_client_escape(http_client, api_key_or_sk_path, strlen(api_key_or_sk_path)))) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(prj_id_or_cert_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(api_key_or_sk_esc);
        http_client_close(http_client);
        return -1;
    }

    body_len = snprintf(NULL, 0, "service=%s&pushservicetype=%s&%s=%s&%s=%s",
                        svc_esc, push_svc_type_esc,
                        !strcmp(push_service_type, "apns") ? "cert" : "projectid",
                        prj_id_or_cert_esc,
                        !strcmp(push_service_type, "apns") ? "key" : "apikey",
                        api_key_or_sk_esc);
    if (body_len <= 0) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(prj_id_or_cert_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(api_key_or_sk_esc);
        http_client_close(http_client);
        return -1;
    }

    body = malloc(body_len + 1);
    if (!body) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(prj_id_or_cert_esc);
        http_client_memory_free(push_svc_type_esc);
        http_client_memory_free(api_key_or_sk_esc);
        http_client_close(http_client);
        return -1;
    }

    snprintf(body, body_len + 1, "service=%s&pushservicetype=%s&%s=%s&%s=%s",
             svc_esc, push_svc_type_esc,
             !strcmp(push_service_type, "apns") ? "cert" : "projectid",
             prj_id_or_cert_esc,
             !strcmp(push_service_type, "apns") ? "key" : "apikey",
             api_key_or_sk_esc);
    http_client_memory_free(svc_esc);
    http_client_memory_free(prj_id_or_cert_esc);
    http_client_memory_free(push_svc_type_esc);
    http_client_memory_free(api_key_or_sk_esc);

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, server->host) ||
        http_client_set_port(http_client, server->port) ||
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

int send_push(const PushServer *server, const char *scope, const char *subscriber, const char *message)
{
    http_client_t *http_client;
    long resp_stat;
    char *body;
    char *suber_esc = NULL;
    char *msg_esc = NULL;
    char *svc_esc = NULL;
    int body_len;
    int rc;

    if (!server || !server->host || !*server->host || !server->port ||
        !*server->port || !scope || !*scope ||
        !subscriber || !*subscriber ||
        !message || !*message)
        return -1;

    http_client = http_client_new();
    if (!http_client)
        return -1;

    if (!(svc_esc = http_client_escape(http_client, scope, strlen(scope))) ||
        !(suber_esc = http_client_escape(http_client, subscriber, strlen(subscriber))) ||
        !(msg_esc = http_client_escape(http_client, message, strlen(message)))) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(msg_esc);
        http_client_close(http_client);
        return -1;
    }

    body_len = snprintf(NULL, 0, "service=%s&subscriber=%s&msg=%s",
                        svc_esc, suber_esc, msg_esc);
    if (body_len <= 0) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(msg_esc);
        http_client_close(http_client);
        return -1;
    }

    body = malloc(body_len + 1);
    if (!body) {
        http_client_memory_free(svc_esc);
        http_client_memory_free(suber_esc);
        http_client_memory_free(msg_esc);
        http_client_close(http_client);
        return -1;
    }

    snprintf(body, body_len + 1, "service=%s&subscriber=%s&msg=%s",
             svc_esc, suber_esc, msg_esc);
    http_client_memory_free(svc_esc);
    http_client_memory_free(suber_esc);
    http_client_memory_free(msg_esc);

    if (http_client_set_method(http_client, HTTP_METHOD_POST) ||
        http_client_set_scheme(http_client, "http") ||
        http_client_set_host(http_client, server->host) ||
        http_client_set_port(http_client, server->port) ||
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
