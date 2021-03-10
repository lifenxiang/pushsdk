/*
 * Copyright (c) 2018 Elastos Foundation
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
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <alloca.h>
#include <getopt.h>

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>

// Undefine Windows defined MOUSE_MOVED for PDCurses
#undef MOUSE_MOVED
#endif

#include <curses.h>

#ifdef __linux__
#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#endif

#include <pthread.h>
#include <push.h>

#define NUMBER_OF_HISTORY       256

static const char *history_filename = ".pushshell.history";

static char *cmd_history[NUMBER_OF_HISTORY];
static int cmd_history_last = 0;
static int cmd_history_cursor = 0;
static int cmd_cursor_dir = 1;
static bool stop;
static push_server_t server;
static bool svr_isset;

WINDOW *output_win_border, *output_win;
WINDOW *log_win_border, *log_win;
WINDOW *cmd_win_border, *cmd_win;

pthread_mutex_t screen_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;

#define OUTPUT_WIN  1
#define LOG_WIN     2
#define CMD_WIN     3

static int OUTPUT_COLS;
static int OUTPUT_LINES = 4;

static void get_layout(int win, int *w, int *h, int *x, int *y)
{
    if (win == OUTPUT_WIN) {
        if (COLS < 100) {
            *x = 0;
            *y = LINES - (LINES -OUTPUT_LINES) / 2 - OUTPUT_LINES;

            *w = COLS;
            *h = (LINES -OUTPUT_LINES) / 2;
        } else {
            *x = 0;
            *y = 0;

            *w = (COLS - 1) / 2;
            *h = LINES - OUTPUT_LINES;
        }

        OUTPUT_COLS = *w -2;
    } else if (win == LOG_WIN) {
        if (COLS < 100) {
            *x = 0;
            *y = 0;

            *w = COLS;
            *h = LINES - (LINES -OUTPUT_LINES) / 2 - OUTPUT_LINES;
        } else {
            *x = COLS - (COLS / 2);
            *y = 0;

            *w = (COLS - 1) / 2;
            *h = LINES - OUTPUT_LINES;
        }
    } else if (win == CMD_WIN) {
        if (COLS < 100) {
            *x = 0;
            *y = LINES - OUTPUT_LINES;

            *w = COLS;
            *h = OUTPUT_LINES;
        } else {
            *x = 0;
            *y = LINES - OUTPUT_LINES;

            *w = COLS;
            *h = OUTPUT_LINES;
        }
    }
}

static void handle_winch(int sig)
{
    int w, h, x, y;

    endwin();

    if (LINES < 20 || COLS < 80) {
        printf("Terminal size too small!\n");
        exit(-1);
    }

    refresh();
    clear();

    wresize(stdscr, LINES, COLS);

    get_layout(OUTPUT_WIN, &w, &h, &x, &y);

    wresize(output_win_border, h, w);
    mvwin(output_win_border, y, x);
    box(output_win_border, 0, 0);
    mvwprintw(output_win_border, 0, 4, "Output");

    wresize(output_win, h-2, w-2);
    mvwin(output_win, y+1, x+1);

    get_layout(LOG_WIN, &w, &h, &x, &y);

    wresize(log_win_border, h, w);
    mvwin(log_win_border, y, x);
    box(log_win_border, 0, 0);
    mvwprintw(log_win_border, 0, 4, "Log");

    wresize(log_win, h-2, w-2);
    mvwin(log_win, y+1,  x+1);

    get_layout(CMD_WIN, &w, &h, &x, &y);

    wresize(cmd_win_border, h, w);
    mvwin(cmd_win_border, y, x);
    box(cmd_win_border, 0, 0);
    mvwprintw(cmd_win_border, 0, 4, "Command");

    wresize(cmd_win, h-2, w-2);
    mvwin(cmd_win,  y+1,  x+1);

    clear();
    refresh();

    wrefresh(output_win_border);
    wrefresh(output_win);

    wrefresh(log_win_border);
    wrefresh(log_win);

    wrefresh(cmd_win_border);
    wrefresh(cmd_win);
}

static void init_screen(void)
{
    int w, h, x, y;

    initscr();

    if (LINES < 20 || COLS < 80) {
        printf("Terminal size too small!\n");
        endwin();
        exit(-1);
    }

    noecho();
    nodelay(stdscr, FALSE);
    refresh();

    get_layout(OUTPUT_WIN, &w, &h, &x, &y);

    output_win_border = newwin(h, w, y, x);
    box(output_win_border, 0, 0);
    mvwprintw(output_win_border, 0, 4, "Output");
    wrefresh(output_win_border);

    output_win = newwin(h-2, w-2, y+1, x+1);
    scrollok(output_win, TRUE);
    wrefresh(output_win);

    get_layout(LOG_WIN, &w, &h, &x, &y);

    log_win_border = newwin(h, w, y, x);
    box(log_win_border, 0, 0);
    mvwprintw(log_win_border, 0, 4, "Log");
    wrefresh(log_win_border);

    log_win = newwin(h-2, w-2, y+1,  x+1);
    scrollok(log_win, TRUE);
    wrefresh(log_win);

    get_layout(CMD_WIN, &w, &h, &x, &y);

    cmd_win_border = newwin(h, w, y, x);
    box(cmd_win_border, 0, 0);
    mvwprintw(cmd_win_border, 0, 4, "Command");
    wrefresh(cmd_win_border);

    cmd_win = newwin(h-2, w-2, y+1,  x+1);
    scrollok(cmd_win, true);
    waddstr(cmd_win, "# ");
    wrefresh(cmd_win);

    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = handle_winch;
    sigaction(SIGWINCH, &sa, NULL);
}

static void cleanup_screen(void)
{
    endwin();

    delwin(output_win_border);
    delwin(output_win);

    delwin(log_win_border);
    delwin(log_win);

    delwin(cmd_win_border);
    delwin(cmd_win);
}

static void history_load(void)
{
    int i = 0;
    char filename[PATH_MAX];
    FILE *fp;
    char line[1024];
    char *p;

    sprintf(filename, "%s/%s", getenv("HOME"), history_filename);

    fp = fopen(filename, "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        // Trim trailing spaces;
        for (p = line + strlen(line) - 1; p >= line && isspace(*p); p--);
        *(++p) = 0;

        // Trim leading spaces;
        for (p = line; *p && isspace(*p); p++);

        if (strlen(p) == 0)
            continue;

        cmd_history[i] = strdup(p);

        i = (i + 1) % NUMBER_OF_HISTORY;
    }

    cmd_history_last = i;
    cmd_history_cursor = cmd_history_last;

    fclose(fp);
}

static void history_save(void)
{
    int i = 0;
    char filename[PATH_MAX];
    FILE *fp;

    sprintf(filename, "%s/%s", getenv("HOME"), history_filename);

    fp = fopen(filename, "w");
    if (!fp)
        return;

    i = cmd_history_last;
    do {
        if (cmd_history[i]) {
            fprintf(fp, "%s\n", cmd_history[i]);
            free(cmd_history[i]);
            cmd_history[i] = NULL;
        }

        i = (i + 1) % NUMBER_OF_HISTORY;
    } while (i != cmd_history_last);

    fclose(fp);
}

static void history_add_cmd(const char *cmd)
{
    if (cmd_history[cmd_history_last])
        free(cmd_history[cmd_history_last]);

    cmd_history[cmd_history_last] = strdup(cmd);

    cmd_history_last = (cmd_history_last + 1) % NUMBER_OF_HISTORY;
    cmd_history_cursor = cmd_history_last;
    cmd_cursor_dir = 1;
}

static const char *history_prev(void)
{
    int n;
    const char *cmd = NULL;

    if (cmd_cursor_dir == -1 &&
        (cmd_history_cursor == cmd_history_last ||
         cmd_history[cmd_history_cursor] == NULL))
        return NULL;

    n = (cmd_history_cursor - 1 + NUMBER_OF_HISTORY) % NUMBER_OF_HISTORY;
    cmd_history_cursor = n;

    if (cmd_history[n])
        cmd = cmd_history[n];

    cmd_cursor_dir = -1;

    return cmd;
}

static const char *history_next(void)
{
    int n;
    const char *cmd = NULL;

    if (cmd_cursor_dir == 1 && cmd_history_cursor == cmd_history_last)
        return NULL;

    n = (cmd_history_cursor + 1) % NUMBER_OF_HISTORY;
    cmd_history_cursor = n;

    if (cmd_history_cursor != cmd_history_last)
        cmd = cmd_history[n];

    cmd_cursor_dir = 1;

    return cmd;
}

static void output(const char *format, ...)
{
    va_list args;

    va_start(args, format);

    pthread_mutex_lock(&screen_lock);
    vwprintw(output_win, format, args);
    wrefresh(output_win);
    wrefresh(cmd_win);
    pthread_mutex_unlock(&screen_lock);

    va_end(args);
}

static void clear_screen(int argc, char *argv[])
{
    if (argc == 1) {
        pthread_mutex_lock(&screen_lock);
        wclear(output_win);
        wrefresh(output_win);
        wclear(log_win);
        wrefresh(log_win);
        wrefresh(cmd_win);
        pthread_mutex_unlock(&screen_lock);
    } else if (argc == 2) {
        WINDOW *w;
        if (strcmp(argv[1], "log") == 0)
            w = log_win;
        else if (strcmp(argv[1], "out") == 0)
            w = output_win;
        else {
            output("Invalid command syntax.\n");
            return;
        }

        pthread_mutex_lock(&screen_lock);
        wclear(w);
        wrefresh(w);
        wrefresh(cmd_win);
        pthread_mutex_unlock(&screen_lock);
    } else {
        output("Invalid command syntax.\n");
        return;
    }
}

static void svr(int argc, char **argv)
{
    if (argc != 3) {
        output("Invalid command syntax.\n");
        return;
    }

    if (svr_isset) {
        free(server.host);
        free(server.port);
    }

    server.host = strdup(argv[1]);
    server.port = strdup(argv[2]);
    svr_isset = true;
}

static void sub(int argc, char *argv[])
{
    int rc;
    struct args {
        const char *cmd;
        const char *scope;
        const char *ev_id;
        union {
            const subscribed_cookie_t cookie;
            const subscribed_project_id_t prj_id;
            const subscribed_dev_token_t dev_token;
        } suber;
    } *args = (struct args *)argv;

    if (argc != 5) {
        output("Invalid command syntax.\n");
        return;
    }

    if (!svr_isset) {
        output("Push server is not set.\n");
        return;
    }

    rc = subscribe_push_service(&server, args->scope, args->ev_id, &args->suber.cookie);
    output("status: %d\n", rc);
}

static void unsub(int argc, char *argv[])
{
    int rc;
    struct args {
        const char *cmd;
        const char *scope;
        const char *ev_id;
        union {
            const subscribed_cookie_t base;
            const subscribed_project_id_t prj_id;
            const subscribed_dev_token_t dev_token;
        } cookie;
    } *args = (struct args *)argv;

    if (argc != 5) {
        output("Invalid command syntax.\n");
        return;
    }

    if (!svr_isset) {
        output("Push server is not set.\n");
        return;
    }

    rc = unsubscribe_push_service(&server, args->scope, args->ev_id, &args->cookie.base);
    output("status: %d\n", rc);
}

static void addpsp(int argc, char *argv[])
{
    int rc;
    struct args {
        const char *cmd;
        const char *scope;
        union {
            const registered_data_t base;
            const registered_project_key_t prj_key;
            const registered_certificate_t cert;
        } data;
    } *args = (struct args *)argv;

    if (argc != 5) {
        output("Invalid command syntax.\n");
        return;
    }

    if (!svr_isset) {
        output("Push server is not set.\n");
        return;
    }

    rc = register_push_service(&server, args->scope, &args->data.base);
    output("status: %d\n", rc);
}

static void rmpsp(int argc, char *argv[])
{
    int rc;
    struct args {
        const char *cmd;
        const char *scope;
        union {
            const registered_data_t base;
            const registered_project_key_t prj_key;
            const registered_certificate_t cert;
        } data;
    } *args = (struct args *)argv;

    if (argc != 5) {
        output("Invalid command syntax.\n");
        return;
    }

    if (!svr_isset) {
        output("Push server is not set.\n");
        return;
    }

    rc = unregister_push_service(&server, args->scope, &args->data.base);
    output("status: %d\n", rc);
}

static void push(int argc, char *argv[])
{
    int rc;
    struct args {
        const char *cmd;
        const char *scope;
        const char *ev_id;
        const char *msg;
    } *args = (struct args *)argv;

    if (argc != 4) {
        output("Invalid command syntax.\n");
        return;
    }

    if (!svr_isset) {
        output("Push server is not set.\n");
        return;
    }

    rc = send_push_message(&server, args->scope, args->ev_id, args->msg);
    output("status: %d\n", rc);
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

    output("{\n");
    if (!strcmp(__data.base->service_type, "fcm")) {
        output(INDENT_FMT "type: fcm,\n", INDENT_ARG(indent_lv + 1));
        output(INDENT_FMT "apikey: %s\n", INDENT_ARG(indent_lv + 1), __data.prj_key->api_key);
    } else {
        output(INDENT_FMT "type: apns,\n", INDENT_ARG(indent_lv + 1));
        output(INDENT_FMT "cert: %s,\n", INDENT_ARG(indent_lv + 1), __data.cert->certificate_path);
        output(INDENT_FMT "key: %s\n", INDENT_ARG(indent_lv + 1), __data.cert->private_key_path);
    }
    output(INDENT_FMT "}", INDENT_ARG(indent_lv));
}

static void output_datas(const registered_data_t **datas, int sz, int indent_lv)
{
    int i;

    output("[\n");
    for (i = 0; i < sz; ++i) {
        output(INDENT_FMT, INDENT_ARG(indent_lv + 1));
        output_data(datas[i], indent_lv + 1);
        output(i == sz - 1 ? "\n" : ",\n");
    }
    output(INDENT_FMT "]", INDENT_ARG(indent_lv));
}

static void output_scope(const scope_registered_datas_t *scope, int indent_lv)
{
    output("{\n");
    output(INDENT_FMT "scope: %s,\n", INDENT_ARG(indent_lv + 1), scope->scope);
    output(INDENT_FMT "datas: ", INDENT_ARG(indent_lv + 1));
    output_datas(scope->datas, scope->size, indent_lv + 1);
    output("\n" INDENT_FMT "}", INDENT_ARG(indent_lv));
}

static void output_scopes(const scope_registered_datas_t *scopes, int sz)
{
    int i;

    output("[\n");
    for (i = 0; i < sz; ++i) {
        output(INDENT_FMT, INDENT_ARG(1));
        output_scope(scopes + i, 1);
        output(i == sz - 1 ? "\n" : ",\n");
    }
    output("]\n");
}

static void list(int argc, char *argv[])
{
    int rc;
    struct args {
        const char *cmd;
    } *args = (struct args *)argv;
    scope_registered_datas_t *scopes;
    int sz;

    if (argc != 1) {
        output("Invalid command syntax.\n");
        return;
    }

    if (!svr_isset) {
        output("Push server is not set.\n");
        return;
    }

    rc = list_registered_push_services(&server, &scopes, &sz);
    output("status: %d\n", rc);

    if (rc != 200)
        return;

    output_scopes(scopes, sz);
    list_registered_push_services_free_scopes(scopes);
}

static void kill_shell(int argc, char **argv)
{
    stop = true;
}

static void help(int argc, char *argv[]);

struct command {
    const char *cmd;
    void (*function)(int argc, char *argv[]);
    const char *help;
} commands[] = {
    { "help",   help,         "help - Display available command list. *OR* help [Command] - Display usage description for specific command." },
    { "clear",  clear_screen, "clear - Clear log and output view in shell. *OR* clear [log | out] - Clear log or output view in shell." },

    { "svr",    svr,          "svr host port - Set push server." },
    { "sub",    sub,          "sub scope suber type regid|devtoken - Subscribe to push service." },
    { "unsub",  unsub,        "unsub scope suber type regid|devtoken - Unsubscribe to push service." },
    { "addpsp", addpsp,       "addpsp scope type prjid|cert apikey|key - Add push service provider." },
    { "rmpsp",  rmpsp,        "rmpsp scope type prjid|cert apikey|key - Remove push service provider." },
    { "push",   push,         "push scope suber msg - Push message." },
    { "list",   list,         "list - List scopes." },

    { "kill",   kill_shell,   "kill - Stop shell." },
    { NULL }
};

static void help(int argc, char *argv[])
{
    char line[256] = "\x0";
    size_t len = 0;
    size_t cmd_len;
    struct command *p;

    if (argc == 1) {
        output(" Use *help [Command]* to see usage description for a specific command.\n Available commands list:\n");

        for (p = commands; p->cmd; p++) {
            cmd_len = strlen(p->cmd);
            if (len + cmd_len + 1 > (size_t)OUTPUT_COLS - 2) {
                output("  %s\n", line);
                strcpy(line, p->cmd);
                strcat(line, " ");
                len = cmd_len + 1;
            } else {
                strcat(line, p->cmd);
                strcat(line, " ");
                len += cmd_len + 1;
            }
        }

        if (len > 0)
            output("  %s\n", line);
    } else {
        for (p = commands; p->cmd; p++) {
            if (strcmp(argv[1], p->cmd) == 0) {
                output("Usage: %s\n", p->help);
                return;
            }
        }

        output("Unknown command: %s\n", argv[1]);
    }
}

static void do_cmd(char *line)
{
    char *args[512];
    int count = 0;
    char *p;
    int word = 0;

    for (p = line; *p != 0; p++) {
        if (isspace(*p)) {
            *p = 0;
            word = 0;
        } else {
            if (word == 0) {
                args[count] = p;
                count++;
            }

            word = 1;
        }
    }

    if (count > 0) {
        struct command *p;

        for (p = commands; p->cmd; p++) {
            if (strcmp(args[0], p->cmd) == 0) {
                p->function(count, args);
                return;
            }
        }

        output("Unknown command: %s\n", args[0]);
    }
}

static char *read_cmd(void)
{
    int x, y;
    int w, h;
    int ch = 0;
    int rc;
    char *p;

    static int cmd_len = 0;
    static char cmd_line[1024];

    ch = getch();
    if (ch == -1)
        return NULL;

    getmaxyx(cmd_win, h, w);
    getyx(cmd_win, y, x);

    (void)h;

    pthread_mutex_lock(&screen_lock);
    if (ch == 10 || ch == 13) {
        rc = mvwinnstr(cmd_win, 0, 2, cmd_line, sizeof(cmd_line));
        mvwinnstr(cmd_win, 1, 0, cmd_line + rc, sizeof(cmd_line) - rc);

        wclear(cmd_win);
        waddstr(cmd_win, "# ");
        wrefresh(cmd_win);
        cmd_len = 0;

        // Trim trailing spaces;
        for (p = cmd_line + strlen(cmd_line) - 1; p >= cmd_line && isspace(*p); p--);
        *(++p) = 0;

        // Trim leading spaces;
        for (p = cmd_line; *p && isspace(*p); p++);

        if (strlen(p)) {
            history_add_cmd(p);
            pthread_mutex_unlock(&screen_lock);
            return p;
        }

    } else if (ch == 127) {
        if (cmd_len > 0 && y * w + x - 2 > 0) {
            if (x == 0) {
                x = w;
                y--;
            }
            wmove(cmd_win, y, x-1);
            wdelch(cmd_win);
            cmd_len--;
        }
    } else if (ch == 27) {
        getch();
        ch = getch();
        if (ch == 65 || ch == 66) {
            p = ch == 65 ? (char *)history_prev() : (char *)history_next();
            wclear(cmd_win);
            waddstr(cmd_win, "# ");
            if (p) waddstr(cmd_win, p);
            cmd_len = p ? (int)strlen(p) : 0;
        } /* else if (ch == 67) {
            if (y * w + x - 2 < cmd_len) {
                if (x == w-1) {
                    x = -1;
                    y++;
                }
                wmove(cmd_win, y, x+1);
            }
        } else if (ch == 68) {
            if (y * w + x - 2 > 0) {
                if (x == 0) {
                    x = w;
                    y--;
                }
                wmove(cmd_win, y, x-1);
            }
        }
        */
    } else {
        if (y * w + x - 2 >= cmd_len) {
            waddch(cmd_win, ch);
        } else {
            winsch(cmd_win, ch);
            wmove(cmd_win, y, x+1);
        }

        cmd_len++;
    }

    wrefresh(cmd_win);
    pthread_mutex_unlock(&screen_lock);

    return NULL;
}

static void usage(void)
{
    printf("Push shell, an interactive console client application.\n");
    printf("Usage: pushshell [OPTION]...\n");
    printf("\n");
    printf("Debugging options:\n");
    printf("      --debug               Wait for debugger attach after start.\n");
    printf("\n");
}


void signal_handler(int signum)
{
    cleanup_screen();
    history_save();
    exit(-1);
}

int main(int argc, char *argv[])
{
    char *cmd;
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

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);
#if !defined(_WIN32) && !defined(_WIN64)
    signal(SIGKILL, signal_handler);
    signal(SIGHUP, signal_handler);
#endif

    init_screen();
    history_load();

    while (!stop) {
        cmd = read_cmd();
        if (cmd)
            do_cmd(cmd);
    }

    cleanup_screen();
    history_save();
    return 0;
}
