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
#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#include <alloca.h>
#include <getopt.h>
#else
#include <crystal.h>
#include <process.h>
#endif

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

static int output_scope(const char *scopes, void *context)
{
    printf("%s\n", scopes);
    return 0;
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

        args = (struct args *)(argv + optind);
        rc = list_push_services(&args->server, output_scope, NULL);
        printf("status: %d\n", rc);
    }

    return 0;
}
