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

#if __linux__
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <getopt.h>

#include <push.h>

static void usage(void)
{
    printf("Push Tool, an CLI tool to simplify push server configuration.\n");
    printf("Usage:\n"
           "  pushtool [OPTION] register | unregister SERVER_HOST SERVER_PORT SCOPE fcm | apns "
           "PROJECT_ID | CERT_PATH API_KEY | KEY_PATH\n"
           "  pushtool [OPTION] list SERVER_HOST SERVER_PORT\n");
    printf("\n");
    printf("Debugging options:\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
}

#define INDENT_FMT "%*s"
#define INDENT_ARG(lv) ((lv) << 1), ""
static void output_data(const registered_data_t *data, int indent_lv)
{
    union {
        const registered_data_t *base;
        const registered_project_key_t *prj_key;
        const registered_certificate_t *cert;
    } __data = {
        .base = data
    };

    printf("{\n");
    if (!strcmp(__data.base->service_type, "fcm")) {
        printf(INDENT_FMT "type: fcm,\n", INDENT_ARG(indent_lv + 1));
        printf(INDENT_FMT "apikey: %s\n", INDENT_ARG(indent_lv + 1), __data.prj_key->api_key);
    } else {
        printf(INDENT_FMT "type: apns,\n", INDENT_ARG(indent_lv + 1));
        printf(INDENT_FMT "cert: %s,\n", INDENT_ARG(indent_lv + 1), __data.cert->certificate_path);
        printf(INDENT_FMT "key: %s\n", INDENT_ARG(indent_lv + 1), __data.cert->private_key_path);
    }
    printf(INDENT_FMT "}", INDENT_ARG(indent_lv));
}

static void output_datas(const registered_data_t **datas, int sz, int indent_lv)
{
    int i;

    printf("[\n");
    for (i = 0; i < sz; ++i) {
        printf(INDENT_FMT, INDENT_ARG(indent_lv + 1));
        output_data(datas[i], indent_lv + 1);
        printf(i == sz - 1 ? "\n" : ",\n");
    }
    printf(INDENT_FMT "]", INDENT_ARG(indent_lv));
}

static void output_scope(const scope_registered_datas_t *scope, int indent_lv)
{
    printf("{\n");
    printf(INDENT_FMT "scope: %s,\n", INDENT_ARG(indent_lv + 1), scope->scope);
    printf(INDENT_FMT "datas: ", INDENT_ARG(indent_lv + 1));
    output_datas(scope->datas, scope->size, indent_lv + 1);
    printf("\n" INDENT_FMT "}", INDENT_ARG(indent_lv));
}

static void output_scopes(const scope_registered_datas_t *scopes, int sz)
{
    int i;

    printf("[\n");
    for (i = 0; i < sz; ++i) {
        printf(INDENT_FMT, INDENT_ARG(1));
        output_scope(scopes + i, 1);
        printf(i == sz - 1 ? "\n" : ",\n");
    }
    printf("]\n");
}

int main(int argc, char *argv[])
{
    int wait_for_attach = 0;
    int rc;
    int opt;
    int idx;
    struct option options[] = {
        { "debug",          no_argument,        NULL, 5 },
        { "help",           no_argument,        NULL, 'h' },
        { NULL,             0,                  NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "c:h?", options, &idx)) != -1) {
        switch (opt) {
        case 5:
            wait_for_attach = 1;
            break;

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

    if (wait_for_attach) {
        printf("Wait for debugger attaching, process id is: %d.\n", getpid());
#ifndef _MSC_VER
        printf("After debugger attached, press any key to continue......");
        getchar();
#else
        DebugBreak();
#endif
    }

    if (argc - optind != 7 && argc - optind != 3) {
        printf("Arguments counts are not correct.");
        return -1;
    }

    if (argc - optind == 7) {
        int (*op)(const push_server_t *, const char *, const registered_data_t *);
        const struct args {
            char *op;
            push_server_t server;
            char *scope;
            union {
                const registered_data_t base;
                const registered_project_key_t prj_key;
                const registered_certificate_t cert;
            } data;
        } *args;

        args = (struct args *)(argv + optind);
        op = !strcmp(args->op, "register") ? register_push_service : unregister_push_service;

        rc = op(&args->server, args->scope, &args->data.base);
        printf("status: %d\n", rc);
    } else {
        const struct args {
            char *op;
            push_server_t server;
        } *args;
        scope_registered_datas_t *scopes;
        int size;

        args = (struct args *)(argv + optind);
        rc = list_registered_push_services(&args->server, &scopes, &size);
        printf("status: %d\n", rc);

        if (rc == 200) {
            output_scopes(scopes, size);
            list_registered_push_services_free_scopes(scopes);
        }
    }

    return 0;
}
