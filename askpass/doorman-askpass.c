/* Doorman's askpass helper.
 *
 * This is the only thing allowed to receive the plaintext secret from the
 * broker on the production path. It talks to the broker over a single Unix
 * socket using only the plain JSON-line protocol: one request line out,
 * one decision line back. No file descriptor is ever sent to the broker.
 *
 * Identity (shape B): this binary is installed setgid with group
 * "doorman-askpass", so when sudo execs it the process runs with that
 * egid. The broker's socket (/run/doorman/askpass.sock) is reachable only
 * through a group ACL for that group, and the broker additionally checks
 * the connecting peer's egid via SO_PEERCRED. There is NO token, NO
 * capability and NO file read of any kind in this binary: the 2026-10-25
 * symlink/env finding (#9558) is closed by removal of the read, not by a
 * guard. The only environment variable consulted is
 * DOORMAN_SOCKET_DEV_OVERRIDE, which exists solely for this binary's own
 * test suite (tests/test_doorman_askpass_c.py) and is never set by
 * anything in production.
 *
 * Non-dumpable: prctl(PR_SET_DUMPABLE, 0) is the very first statement of
 * main(). This is mandatory and must not rely on the setgid side effect:
 * with fs.suid_dumpable != 0 a setgid exec can otherwise stay dumpable and
 * let a same-uid process ptrace it or read its memory.
 *
 * Linking decision: kept dynamically linked. This is now safe against
 * LD_PRELOAD because the setgid exec sets AT_SECURE=1, so the loader
 * ignores LD_PRELOAD and other LD_* variables from the environment.
 * Static linking remains an optional belt-and-suspenders measure.
 *
 * Deliberately self-contained: no exec, no libraries beyond libc, one
 * source file.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE (16 * 1024)
#define ASKPASS_SOCKET_PATH "/run/doorman/askpass.sock"

static ssize_t write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return (ssize_t)len;
}

/* Reads one '\n'-terminated line, bounded to buf_size - 1 bytes (matching
 * the protocol's own MAX_LINE on both the broker and client.py), into buf.
 * Returns the line length (excluding the newline) or -1 on error, timeout,
 * EOF, or overflow — there is no partial-success case callers should act
 * on. */
static ssize_t read_line(int fd, char *buf, size_t buf_size) {
    size_t len = 0;
    for (;;) {
        if (len + 1 >= buf_size) return -1;
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        if (c == '\n') {
            buf[len] = '\0';
            return (ssize_t)len;
        }
        buf[len++] = c;
    }
}

/* Appends src as a JSON string literal (including the surrounding quotes)
 * to dst, which must already be NUL-terminated or empty. Returns the new
 * length of dst, or -1 if it would overflow dst_size. */
static int write_json_string(char *dst, size_t dst_size, const char *src) {
    size_t di = strlen(dst);
    if (di + 1 >= dst_size) return -1;
    dst[di++] = '"';
    for (const unsigned char *s = (const unsigned char *)src; *s; s++) {
        unsigned char c = *s;
        char esc[8];
        const char *rep = NULL;
        switch (c) {
            case '"': rep = "\\\""; break;
            case '\\': rep = "\\\\"; break;
            case '\n': rep = "\\n"; break;
            case '\r': rep = "\\r"; break;
            case '\t': rep = "\\t"; break;
            default:
                if (c < 0x20) {
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    rep = esc;
                }
        }
        if (rep) {
            size_t elen = strlen(rep);
            if (di + elen >= dst_size) return -1;
            memcpy(dst + di, rep, elen);
            di += elen;
        } else {
            if (di + 1 >= dst_size) return -1;
            dst[di++] = (char)c;
        }
    }
    if (di + 2 >= dst_size) return -1;
    dst[di++] = '"';
    dst[di] = '\0';
    return (int)di;
}

static const char *find_key(const char *line, const char *key) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(line, needle);
    return p ? p + strlen(needle) : NULL;
}

static int parse_bool_field(const char *line, const char *key, int *out) {
    const char *v = find_key(line, key);
    if (!v) return -1;
    if (strncmp(v, "true", 4) == 0) {
        *out = 1;
        return 0;
    }
    if (strncmp(v, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int parse_number_field(const char *line, const char *key, double *out) {
    const char *v = find_key(line, key);
    if (!v) return -1;
    char *end;
    double d = strtod(v, &end);
    if (end == v) return -1;
    *out = d;
    return 0;
}

/* The one routine every string field this program reads goes through — a
 * naive "scan to the next quote" parser desyncs or truncates on a
 * human-typed secret containing a literal '"' or '\', which is valid input
 * today (the broker only caps secret length, at 4096 bytes). Handles the
 * standard single-letter escapes plus \uXXXX (encoded back to UTF-8; this
 * protocol never emits surrogate pairs, so BMP-only is sufficient). */
static int parse_string_field(const char *line, const char *key, char *out,
                                size_t out_size) {
    const char *p = find_key(line, key);
    if (!p || *p != '"') return -1;
    p++;
    size_t oi = 0;
    while (*p) {
        char c = *p;
        if (c == '"') {
            if (oi >= out_size) return -1;
            out[oi] = '\0';
            return 0;
        }
        if (c == '\\') {
            p++;
            char decoded;
            switch (*p) {
                case '"': decoded = '"'; break;
                case '\\': decoded = '\\'; break;
                case '/': decoded = '/'; break;
                case 'b': decoded = '\b'; break;
                case 'f': decoded = '\f'; break;
                case 'n': decoded = '\n'; break;
                case 'r': decoded = '\r'; break;
                case 't': decoded = '\t'; break;
                case 'u': {
                    unsigned int cp = 0;
                    for (int i = 1; i <= 4; i++) {
                        char hc = p[i];
                        unsigned int digit;
                        if (hc >= '0' && hc <= '9') digit = (unsigned)(hc - '0');
                        else if (hc >= 'a' && hc <= 'f') digit = (unsigned)(hc - 'a' + 10);
                        else if (hc >= 'A' && hc <= 'F') digit = (unsigned)(hc - 'A' + 10);
                        else return -1;
                        cp = (cp << 4) | digit;
                    }
                    p += 4;
                    if (cp < 0x80) {
                        if (oi + 1 > out_size) return -1;
                        out[oi++] = (char)cp;
                    } else if (cp < 0x800) {
                        if (oi + 2 > out_size) return -1;
                        out[oi++] = (char)(0xC0 | (cp >> 6));
                        out[oi++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        if (oi + 3 > out_size) return -1;
                        out[oi++] = (char)(0xE0 | (cp >> 12));
                        out[oi++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        out[oi++] = (char)(0x80 | (cp & 0x3F));
                    }
                    p++;
                    continue;
                }
                default:
                    return -1;
            }
            if (oi + 1 > out_size) return -1;
            out[oi++] = decoded;
            p++;
            continue;
        }
        if (oi + 1 > out_size) return -1;
        out[oi++] = c;
        p++;
    }
    return -1; /* unterminated string */
}

int main(int argc, char **argv) {
    if (prctl(PR_SET_DUMPABLE, 0) != 0) return 1;

    const char *prompt = (argc > 1) ? argv[1] : "Password: ";

    const char *socket_override = getenv("DOORMAN_SOCKET_DEV_OVERRIDE");
    char socket_path[800];
    snprintf(socket_path, sizeof(socket_path), "%s",
              (socket_override && *socket_override) ? socket_override
                                                    : ASKPASS_SOCKET_PATH);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        return 1;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    struct timeval handshake_tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &handshake_tv, sizeof(handshake_tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &handshake_tv, sizeof(handshake_tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 1;
    }

    char cwd[700];
    if (!getcwd(cwd, sizeof(cwd))) cwd[0] = '\0';

    char esc_prompt[1200] = "";
    char esc_cwd[1500] = "";
    if (write_json_string(esc_prompt, sizeof(esc_prompt), prompt) < 0 ||
        write_json_string(esc_cwd, sizeof(esc_cwd), cwd) < 0) {
        close(fd);
        return 1;
    }

    /* "command" is intentionally a static, non-authoritative placeholder:
     * the broker derives the displayed command itself from the real sudo
     * parent's own cmdline (SPEC.md §6.12) rather than trusting anything
     * sent here, so there is nothing security-relevant to put in this
     * field. */
    char request[8192];
    int n = snprintf(
        request, sizeof(request),
        "{\"type\":\"request\",\"pid\":%d,\"sudo_pid\":%d,"
        "\"command\":\"sudo askpass\",\"cwd\":%s,\"tty\":\"\",\"prompt\":%s}\n",
        (int)getpid(), (int)getppid(), esc_cwd, esc_prompt);
    if (n < 0 || (size_t)n >= sizeof(request)) {
        close(fd);
        return 1;
    }

    if (write_all(fd, request, (size_t)n) < 0) {
        close(fd);
        return 1;
    }

    char line[MAX_LINE + 1];
    if (read_line(fd, line, sizeof(line)) < 0) {
        close(fd);
        return 1;
    }

    int accepted_ok = 0;
    if (parse_bool_field(line, "ok", &accepted_ok) != 0 || !accepted_ok) {
        close(fd);
        return 1;
    }

    double expires_at = 0;
    struct timeval decision_tv;
    if (parse_number_field(line, "expires_at", &expires_at) == 0) {
        double wait = expires_at - (double)time(NULL) + 2.0;
        if (wait < 0) wait = 0;
        if (wait > 305.0) wait = 305.0;
        decision_tv.tv_sec = (long)wait;
        decision_tv.tv_usec = (long)((wait - (double)(long)wait) * 1000000.0);
    } else {
        decision_tv.tv_sec = 305;
        decision_tv.tv_usec = 0;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &decision_tv, sizeof(decision_tv));

    ssize_t len = read_line(fd, line, sizeof(line));
    close(fd);
    if (len < 0) return 1;

    int ok = 0;
    if (parse_bool_field(line, "ok", &ok) != 0 || !ok) return 1;

    char secret[4097];
    if (parse_string_field(line, "secret", secret, sizeof(secret)) != 0) return 1;

    size_t secret_len = strlen(secret);
    int rc = 1;
    if (write_all(STDOUT_FILENO, secret, secret_len) == (ssize_t)secret_len &&
        write_all(STDOUT_FILENO, "\n", 1) == 1) {
        rc = 0;
    }
    explicit_bzero(secret, sizeof(secret));
    return rc;
}
