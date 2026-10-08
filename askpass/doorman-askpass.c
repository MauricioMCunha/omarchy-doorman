/* Doorman's askpass helper.
 *
 * This is the only thing allowed to receive the plaintext secret from the
 * broker on the production path. sudo lets the *caller* choose the
 * SUDO_ASKPASS helper (there is no restriction on what that helper is), so
 * an agent that invokes real sudo directly can point SUDO_ASKPASS at code
 * it wrote itself — a genuine child of a genuinely privilege-escalated real
 * sudo, which passes every check the broker can make about that parent
 * (issue #9558). The broker closes that by also requiring the *peer
 * itself* — this process — to prove it actually is this exact file: it
 * opens its own /proc/self/exe and hands that file descriptor to the
 * broker over the request socket via SCM_RIGHTS ancillary data, alongside
 * the normal JSON request line. The broker fstat()s the fd it receives —
 * comparing device+inode, not any path string — against the fixed,
 * root-owned path this binary is installed at once by root
 * (scripts/doorman-install-askpass), outside this project's user-writable
 * git checkout. That installed file is also mode 0711 (executable, not
 * readable, by anyone but root): an attacker can't open() it by path and
 * send *that* fd instead, so the only way to produce a matching fd at all
 * is to have genuinely exec'd this exact file.
 *
 * Opening our own /proc/self/exe is NOT privilege-exempt — it is subject
 * to the exact same DAC read check as opening the target file by its real
 * path, confirmed live (EACCES on every attempt under plain mode 0711 as
 * the non-root invoking user, legitimate caller included). So the
 * installed binary also carries a file capability, cap_dac_read_search
 * (set by the install script via setcap, never by this binary itself),
 * which lets *this process* bypass that one read check without running as
 * root or gaining any other privilege — unlike setuid-root, a
 * memory-safety bug here can't turn into arbitrary code execution as
 * root, only into reading something it otherwise couldn't. See SPEC.md
 * §6.11 for the full history, including why this isn't just a plain
 * stat() of the *peer's* /proc/<pid>/exe by the broker (the first thing
 * tried — needs a ptrace-equivalent capability the broker's own hardened
 * systemd unit denies it by design), and why that in turn replaced an
 * earlier setgid-plus-SO_PEERCRED-gid design (the broker's own sandboxing
 * couldn't reliably resolve the peer's gid either).
 *
 * Deliberately self-contained: no exec, no libraries beyond libc, one
 * source file. Nothing here execs anything else, so there's no second
 * process whose environment (PYTHONPATH, LD_PRELOAD, ...) a caller who
 * chose us as SUDO_ASKPASS could try to influence.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE (16 * 1024)

static char *read_file_trim(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(MAX_LINE + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, MAX_LINE, f);
    fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                      buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[--n] = '\0';
    }
    size_t start = 0;
    while (buf[start] == ' ' || buf[start] == '\t' || buf[start] == '\n' ||
           buf[start] == '\r') {
        start++;
    }
    if (start > 0) memmove(buf, buf + start, n - start + 1);
    return buf;
}

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

/* Sends buf like write_all(), except the first write() is a sendmsg()
 * carrying identity_fd as SCM_RIGHTS ancillary data — see the top comment
 * for why: this is how the broker learns the connecting peer really did
 * exec the trusted binary, without needing any permission over this
 * process from the broker's side. The rare case of a short first write
 * (the request line is a few hundred bytes, well under a socket buffer,
 * so in practice this never happens) falls back to a plain write() for
 * the remainder — the fd has already been delivered by then. */
static ssize_t send_request_with_identity(int sockfd, const char *buf,
                                            size_t len, int identity_fd) {
    struct iovec iov = {.iov_base = (void *)buf, .iov_len = len};
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &identity_fd, sizeof(int));

    for (;;) {
        ssize_t n = sendmsg(sockfd, &msg, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if ((size_t)n == len) return n;
        return write_all(sockfd, buf + n, len - (size_t)n) < 0 ? -1 : (ssize_t)len;
    }
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
    const char *prompt = (argc > 1) ? argv[1] : "Password: ";

    const char *xdg = getenv("XDG_RUNTIME_DIR");
    char runtime_dir[768];
    if (xdg && *xdg) {
        snprintf(runtime_dir, sizeof(runtime_dir), "%s/omarchy-doorman", xdg);
    } else {
        snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%d/omarchy-doorman",
                  (int)getuid());
    }

    char token_path[800], cap_path[800];
    snprintf(token_path, sizeof(token_path), "%s/token", runtime_dir);
    snprintf(cap_path, sizeof(cap_path), "%s/llm-capability", runtime_dir);

    char *token = read_file_trim(token_path);
    char *capability = read_file_trim(cap_path);
    if (!token || !*token || !capability || !*capability) {
        free(token);
        free(capability);
        return 2;
    }

    const char *socket_env = getenv("DOORMAN_SOCKET");
    char socket_path[800];
    if (socket_env && *socket_env) {
        snprintf(socket_path, sizeof(socket_path), "%s", socket_env);
    } else {
        snprintf(socket_path, sizeof(socket_path), "%s/broker.sock", runtime_dir);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        free(token);
        free(capability);
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        close(fd);
        free(token);
        free(capability);
        return 1;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    struct timeval handshake_tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &handshake_tv, sizeof(handshake_tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &handshake_tv, sizeof(handshake_tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        free(token);
        free(capability);
        return 1;
    }

    char cwd[700];
    if (!getcwd(cwd, sizeof(cwd))) cwd[0] = '\0';

    char esc_token[2200] = "";
    char esc_capability[1200] = "";
    char esc_prompt[1200] = "";
    char esc_cwd[1500] = "";
    if (write_json_string(esc_token, sizeof(esc_token), token) < 0 ||
        write_json_string(esc_capability, sizeof(esc_capability), capability) < 0 ||
        write_json_string(esc_prompt, sizeof(esc_prompt), prompt) < 0 ||
        write_json_string(esc_cwd, sizeof(esc_cwd), cwd) < 0) {
        close(fd);
        free(token);
        free(capability);
        return 1;
    }
    free(token);
    free(capability);

    /* "command" is intentionally a static, non-authoritative placeholder:
     * the broker derives the displayed command itself from the real sudo
     * parent's own cmdline (SPEC.md §6.12) rather than trusting anything
     * sent here, so there is nothing security-relevant to put in this
     * field. */
    char request[8192];
    int n = snprintf(
        request, sizeof(request),
        "{\"token\":%s,\"type\":\"request\",\"pid\":%d,\"sudo_pid\":%d,"
        "\"command\":\"sudo askpass\",\"cwd\":%s,\"tty\":\"\",\"prompt\":%s,"
        "\"origin\":\"llm\",\"capability\":%s}\n",
        esc_token, (int)getpid(), (int)getppid(), esc_cwd, esc_prompt, esc_capability);
    if (n < 0 || (size_t)n >= sizeof(request)) {
        close(fd);
        return 1;
    }

    int identity_fd = open("/proc/self/exe", O_RDONLY);
    if (identity_fd < 0) {
        fprintf(stderr,
                "doorman-askpass: cannot read own executable (open "
                "/proc/self/exe: %s) — is cap_dac_read_search set? run "
                "scripts/doorman-install-askpass as root\n",
                strerror(errno));
        close(fd);
        return 1;
    }
    if (send_request_with_identity(fd, request, (size_t)n, identity_fd) < 0) {
        close(identity_fd);
        close(fd);
        return 1;
    }
    close(identity_fd);

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
