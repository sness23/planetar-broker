/*
 * planetar-broker — phase 3
 *
 * Native zmesg envelope bus. TCP + UDP + WAL (CRC32). SHM ships in phase 4.
 *
 * Producers connect to 127.0.0.1:12001 and stream length-prefixed frames:
 *     [u32 length, big-endian (network byte order)]
 *     [length bytes: zmesg envelope]
 *
 * Consumers connect to 127.0.0.1:12002, send a one-line subscribe
 *     "SUB <topic>[ <topic>]*\n"            (max 1 KiB, up to 32 topics)
 * and the broker replies
 *     "OK\n"          on success
 *     "ERR <reason>\n"  on failure (then closes)
 * Subsequent bytes are length-prefixed frames matching one of the subscribed
 * topics. The special topic "**" matches every envelope.
 *
 * Topic matching uses the topic field stored *inside* the zmesg envelope
 * (offset 48..50 = topic_len, offset 66 = topic start). The broker never
 * inspects the payload.
 *
 * Single-threaded epoll loop. Backpressure is drop-oldest: if a subscriber's
 * pending write queue exceeds OUTQ_MAX_BYTES we discard the oldest queued
 * frames and bump a per-client counter.
 *
 * UDP: producers can also send datagrams to 127.0.0.1:12003. Each datagram
 * is exactly one zmesg envelope (no length prefix — UDP datagram boundary
 * frames it). The broker fans these out to TCP subscribers using the same
 * length-prefixed TCP framing. No UDP-as-subscriber in this phase.
 *
 * WAL: every valid envelope is appended to a segment file under WAL_DIR
 * (default ./wal/) before fan-out. Entry layout:
 *     [u16 magic=0xB10C][u16 origin][u32 data_len][u64 sequence]
 *     [u64 timestamp_ns][u32 crc32][u32 total_len][data bytes]
 * Segments are 64 MiB; segment header is "WAL1" + base_sequence + metadata.
 * On startup the broker scans WAL_DIR, finds the latest segment, walks its
 * entries to recover the next sequence number, then opens a fresh segment.
 * CRC32 uses the standard IEEE polynomial 0xEDB88320, computed over data.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* ---------------- tunables ---------------- */

#define PUB_PORT             12001
#define SUB_PORT             12002
#define UDP_PORT             12003

#define UDP_RECV_MAX         65535
#define LISTEN_BACKLOG       64
#define READ_CHUNK           8192
#define FRAME_MAX_LEN        (1u << 20)    /* 1 MiB per envelope */
#define SUB_LINE_MAX         1024
#define MAX_TOPICS_PER_SUB   32
#define OUTQ_MAX_BYTES       (1u << 20)    /* 1 MiB pending per sub */
#define EPOLL_BATCH          64

/* zmesg envelope offsets (mirrors zmesg.h) */
#define ZMESG_MAGIC          0x5A4D5347u    /* "ZMSG" read little-endian */
#define ZMESG_FIXED_HDR      66u
#define ZMESG_OFF_TOPIC_LEN  48u

/* WAL constants */
#define WAL_DIR_DEFAULT      "./wal"
#define WAL_SEG_MAX_BYTES    (64u * 1024 * 1024)    /* 64 MiB per segment */
#define WAL_ENTRY_MAGIC      0xB10Cu
#define WAL_SEG_MAGIC        0x57414C31u             /* "WAL1" */
#define WAL_SEG_VERSION      1u
#define WAL_ALIGN            8u

/* ---------------- logging ---------------- */

static void log_msg(const char *level, const char *fmt, ...) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char tbuf[32];
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tm);
    fprintf(stderr, "[%s.%03ld %s] ", tbuf, ts.tv_nsec / 1000000, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}
#define LOG_INFO(...)  log_msg("info", __VA_ARGS__)
#define LOG_WARN(...)  log_msg("warn", __VA_ARGS__)
#define LOG_ERR(...)   log_msg("err",  __VA_ARGS__)

/* ---------------- CRC32 (IEEE 0xEDB88320) ---------------- */

static uint32_t crc32_table[256];
static int crc32_table_built = 0;

static void crc32_build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_built = 1;
}

static uint32_t crc32_calc(const uint8_t *data, size_t len) {
    if (!crc32_table_built) crc32_build_table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc32_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---------------- WAL ---------------- */

typedef enum {
    ORIGIN_TCP = 0,
    ORIGIN_UDP = 1,
    ORIGIN_SHM = 2,
} msg_origin_t;

typedef struct {
    uint16_t magic;          /*  0: 0xB10C                  */
    uint16_t origin;         /*  2: msg_origin_t            */
    uint32_t data_len;       /*  4: zmesg envelope length   */
    uint64_t sequence;       /*  8: global monotonic ID     */
    uint64_t timestamp_ns;   /* 16: CLOCK_REALTIME          */
    uint32_t crc32;          /* 24: CRC32 over data         */
    uint32_t total_len;      /* 28: aligned entry size      */
    /* data[] follows */
} __attribute__((packed)) wal_entry_hdr_t;

typedef struct {
    uint32_t magic;            /*  0: 0x57414C31 ("WAL1")  */
    uint32_t version;          /*  4: 1                    */
    uint64_t base_sequence;    /*  8: first entry's seq    */
    uint64_t created_ns;       /* 16: creation timestamp   */
    uint32_t entry_count;      /* 24: entries written      */
    uint32_t flags;            /* 28: bit 0 = clean close  */
    uint8_t  reserved[32];     /* 32: future use           */
} __attribute__((packed)) wal_seg_header_t;

typedef struct {
    char     dir[256];
    int      fd;
    uint64_t base_sequence;
    uint64_t entry_count;
    size_t   bytes_written;     /* including segment header */
    char     path[512];
    int      enabled;
} wal_t;

static wal_t g_wal;
static uint64_t g_sequence = 0;

static uint64_t now_ns_real(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int ensure_dir(const char *dir) {
    if (mkdir(dir, 0755) == 0) return 0;
    if (errno == EEXIST) return 0;
    LOG_ERR("mkdir %s: %s", dir, strerror(errno));
    return -1;
}

static void wal_segment_path(char *out, size_t cap, const char *dir, uint64_t base_seq) {
    snprintf(out, cap, "%s/segment-%012llu.wal", dir, (unsigned long long)base_seq);
}

static int wal_open_new_segment(wal_t *w, uint64_t base_sequence) {
    wal_segment_path(w->path, sizeof w->path, w->dir, base_sequence);
    int fd = open(w->path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOG_ERR("open %s: %s", w->path, strerror(errno));
        return -1;
    }
    wal_seg_header_t hdr = {0};
    hdr.magic = WAL_SEG_MAGIC;
    hdr.version = WAL_SEG_VERSION;
    hdr.base_sequence = base_sequence;
    hdr.created_ns = now_ns_real();
    hdr.entry_count = 0;
    hdr.flags = 0;
    if (write(fd, &hdr, sizeof hdr) != (ssize_t)sizeof hdr) {
        LOG_ERR("write seg header %s: %s", w->path, strerror(errno));
        close(fd);
        return -1;
    }
    w->fd = fd;
    w->base_sequence = base_sequence;
    w->entry_count = 0;
    w->bytes_written = sizeof hdr;
    LOG_INFO("WAL segment open %s (base_seq=%llu)",
             w->path, (unsigned long long)base_sequence);
    return 0;
}

/*
 * Mark current segment as cleanly closed by rewriting its header flags+count.
 * Best-effort; not fatal if it fails.
 */
static void wal_finalize_segment(wal_t *w) {
    if (w->fd < 0) return;
    int rfd = open(w->path, O_WRONLY | O_CLOEXEC);
    if (rfd >= 0) {
        wal_seg_header_t hdr = {0};
        hdr.magic = WAL_SEG_MAGIC;
        hdr.version = WAL_SEG_VERSION;
        hdr.base_sequence = w->base_sequence;
        hdr.created_ns = now_ns_real();
        hdr.entry_count = (uint32_t)w->entry_count;
        hdr.flags = 1u;
        if (pwrite(rfd, &hdr, sizeof hdr, 0) != (ssize_t)sizeof hdr)
            LOG_WARN("pwrite finalize %s: %s", w->path, strerror(errno));
        fsync(rfd);
        close(rfd);
    }
    fsync(w->fd);
    close(w->fd);
    w->fd = -1;
}

static int wal_append(wal_t *w, const uint8_t *data, size_t len, msg_origin_t origin) {
    if (!w->enabled || w->fd < 0) return 0;

    size_t padded = (len + (WAL_ALIGN - 1)) & ~((size_t)WAL_ALIGN - 1);
    size_t total = sizeof(wal_entry_hdr_t) + padded;

    if (w->bytes_written + total > WAL_SEG_MAX_BYTES) {
        uint64_t next_base = w->base_sequence + w->entry_count;
        wal_finalize_segment(w);
        if (wal_open_new_segment(w, next_base) < 0) {
            w->enabled = 0;
            return -1;
        }
    }

    g_sequence++;
    wal_entry_hdr_t hdr = {0};
    hdr.magic = WAL_ENTRY_MAGIC;
    hdr.origin = (uint16_t)origin;
    hdr.data_len = (uint32_t)len;
    hdr.sequence = g_sequence;
    hdr.timestamp_ns = now_ns_real();
    hdr.crc32 = crc32_calc(data, len);
    hdr.total_len = (uint32_t)total;

    struct iovec iov[3];
    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof hdr;
    iov[1].iov_base = (void *)data;
    iov[1].iov_len = len;
    static const uint8_t pad[WAL_ALIGN] = {0};
    iov[2].iov_base = (void *)pad;
    iov[2].iov_len = padded - len;
    int niov = iov[2].iov_len ? 3 : 2;

    ssize_t expected = (ssize_t)(sizeof hdr + len + iov[2].iov_len);
    ssize_t got = writev(w->fd, iov, niov);
    if (got != expected) {
        LOG_ERR("WAL writev short=%zd expected=%zd: %s",
                got, expected, got < 0 ? strerror(errno) : "partial");
        w->enabled = 0;
        return -1;
    }
    w->entry_count++;
    w->bytes_written += total;
    return 0;
}

/*
 * Scan an existing segment from its header forward, count valid entries,
 * and return one past the last valid sequence. Stops at the first invalid
 * entry (corruption / partial write).
 */
static int wal_scan_segment(const char *path, uint64_t *out_next_seq, uint64_t *out_count) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    wal_seg_header_t shdr;
    if (read(fd, &shdr, sizeof shdr) != (ssize_t)sizeof shdr || shdr.magic != WAL_SEG_MAGIC) {
        close(fd);
        return -1;
    }
    uint64_t base = shdr.base_sequence;
    uint64_t count = 0;
    uint64_t last_seq = base; /* if no entries, "next" is base itself */

    for (;;) {
        wal_entry_hdr_t eh;
        ssize_t r = read(fd, &eh, sizeof eh);
        if (r == 0) break;
        if (r != (ssize_t)sizeof eh || eh.magic != WAL_ENTRY_MAGIC) break;
        size_t padded = (eh.data_len + (WAL_ALIGN - 1)) & ~((size_t)WAL_ALIGN - 1);
        if (lseek(fd, (off_t)padded, SEEK_CUR) < 0) break;
        last_seq = eh.sequence;
        count++;
    }
    close(fd);
    *out_next_seq = last_seq + (count ? 1 : 0);
    *out_count = count;
    return 0;
}

static int wal_init(wal_t *w, const char *dir) {
    memset(w, 0, sizeof *w);
    w->fd = -1;
    snprintf(w->dir, sizeof w->dir, "%s", dir);
    if (ensure_dir(w->dir) < 0) return -1;

    DIR *d = opendir(w->dir);
    if (!d) { LOG_ERR("opendir %s: %s", w->dir, strerror(errno)); return -1; }

    char latest_name[256] = {0};
    uint64_t latest_base = 0;
    int found = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        unsigned long long base = 0;
        if (sscanf(de->d_name, "segment-%llu.wal", &base) != 1) continue;
        if (!found || base > latest_base) {
            latest_base = base;
            snprintf(latest_name, sizeof latest_name, "%s", de->d_name);
            found = 1;
        }
    }
    closedir(d);

    uint64_t next_seq = 0;
    if (found) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s", w->dir, latest_name);
        uint64_t count = 0;
        if (wal_scan_segment(path, &next_seq, &count) < 0) {
            LOG_WARN("WAL scan failed for %s; starting fresh", path);
            next_seq = latest_base + 1000000;  /* leave room rather than collide */
        } else {
            LOG_INFO("WAL recovered: %s base=%llu entries=%llu next_seq=%llu",
                     latest_name, (unsigned long long)latest_base,
                     (unsigned long long)count, (unsigned long long)next_seq);
        }
    } else {
        LOG_INFO("WAL fresh start in %s", w->dir);
    }

    g_sequence = next_seq;
    w->enabled = 1;
    if (wal_open_new_segment(w, g_sequence) < 0) {
        w->enabled = 0;
        return -1;
    }
    return 0;
}

static void wal_close(wal_t *w) {
    if (w->fd >= 0) wal_finalize_segment(w);
    w->enabled = 0;
}

/* ---------------- epoll dispatch tag ---------------- */

typedef enum {
    EV_LISTEN_PUB,
    EV_LISTEN_SUB,
    EV_LISTEN_UDP,
    EV_CLIENT,
} ev_kind_t;

typedef struct ev_handle {
    ev_kind_t kind;
} ev_handle_t;

/* ---------------- client state ---------------- */

typedef enum {
    CK_PUB,
    CK_SUB,
} client_kind_t;

typedef enum {
    SS_HANDSHAKE,   /* awaiting "SUB ..." line */
    SS_RUNNING,
} sub_state_t;

typedef struct outq_entry {
    struct outq_entry *next;
    size_t   total;   /* total bytes in `frame` */
    size_t   sent;    /* bytes already written */
    uint8_t  frame[]; /* length-prefixed wire frame */
} outq_entry_t;

typedef struct client {
    ev_handle_t   ev;     /* MUST be first — epoll data.ptr looks at this */
    int           fd;
    client_kind_t kind;
    sub_state_t   sub_state;

    /* read buffer */
    uint8_t      *rbuf;
    size_t        rlen;
    size_t        rcap;

    /* sub state */
    char         *topics[MAX_TOPICS_PER_SUB];
    size_t        n_topics;
    int           match_all;

    /* outgoing queue */
    outq_entry_t *outq_head, *outq_tail;
    size_t        outq_bytes;
    uint64_t      dropped;
    int           want_write;

    char          peer[64];
} client_t;

/* ---------------- globals ---------------- */

static int g_epoll_fd = -1;
static volatile sig_atomic_t g_stop = 0;
static unsigned long long g_pub_msgs = 0;
static unsigned long long g_pub_bytes = 0;
static unsigned long long g_delivered = 0;

static void on_sigint(int signo) { (void)signo; g_stop = 1; }

/* ---------------- utility ---------------- */

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int set_nodelay(int fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

static int listen_tcp(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { LOG_ERR("socket: %s", strerror(errno)); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        LOG_ERR("bind %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, LISTEN_BACKLOG) < 0) {
        LOG_ERR("listen %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        LOG_ERR("nonblock %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    LOG_INFO("listening 127.0.0.1:%d (TCP)", port);
    return fd;
}

static int bind_udp(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { LOG_ERR("udp socket: %s", strerror(errno)); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        LOG_ERR("udp bind %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (set_nonblock(fd) < 0) {
        LOG_ERR("udp nonblock %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    /* Bump receive buffer for bursty publishers */
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

    LOG_INFO("listening 127.0.0.1:%d (UDP)", port);
    return fd;
}

/* ---------------- buffer growth ---------------- */

static int rbuf_grow(client_t *c, size_t need) {
    if (need <= c->rcap) return 0;
    if (need > FRAME_MAX_LEN + 4) return -1;
    size_t cap = c->rcap ? c->rcap : READ_CHUNK;
    while (cap < need) cap *= 2;
    if (cap > FRAME_MAX_LEN + 4) cap = FRAME_MAX_LEN + 4;
    uint8_t *nb = realloc(c->rbuf, cap);
    if (!nb) return -1;
    c->rbuf = nb;
    c->rcap = cap;
    return 0;
}

/* ---------------- outq ---------------- */

static void outq_free_all(client_t *c) {
    outq_entry_t *e = c->outq_head;
    while (e) {
        outq_entry_t *n = e->next;
        free(e);
        e = n;
    }
    c->outq_head = c->outq_tail = NULL;
    c->outq_bytes = 0;
}

static int outq_push(client_t *c, const uint8_t *frame, size_t total) {
    /* drop-oldest backpressure */
    while (c->outq_bytes + total > OUTQ_MAX_BYTES && c->outq_head) {
        outq_entry_t *e = c->outq_head;
        c->outq_head = e->next;
        if (!c->outq_head) c->outq_tail = NULL;
        c->outq_bytes -= (e->total - e->sent);
        c->dropped++;
        free(e);
    }
    outq_entry_t *e = malloc(sizeof *e + total);
    if (!e) return -1;
    e->next = NULL;
    e->total = total;
    e->sent = 0;
    memcpy(e->frame, frame, total);
    if (c->outq_tail) c->outq_tail->next = e;
    else c->outq_head = e;
    c->outq_tail = e;
    c->outq_bytes += total;
    return 0;
}

static int try_flush(client_t *c) {
    while (c->outq_head) {
        outq_entry_t *e = c->outq_head;
        ssize_t n = write(c->fd, e->frame + e->sent, e->total - e->sent);
        if (n > 0) {
            e->sent += (size_t)n;
            c->outq_bytes -= (size_t)n;
            if (e->sent == e->total) {
                c->outq_head = e->next;
                if (!c->outq_head) c->outq_tail = NULL;
                free(e);
            }
            continue;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        return -1; /* n == 0: write returned 0 unexpectedly */
    }
    return 0;
}

static void update_epoll_mode(client_t *c) {
    int want = c->outq_head ? (EPOLLIN | EPOLLOUT) : EPOLLIN;
    if (want == c->want_write) return;
    struct epoll_event ev = { .events = (uint32_t)want, .data.ptr = c };
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev) == 0) c->want_write = want;
}

/* ---------------- client lifecycle ---------------- */

static client_t *client_new(int fd, client_kind_t kind, const struct sockaddr_in *sa) {
    client_t *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->ev.kind = EV_CLIENT;
    c->fd = fd;
    c->kind = kind;
    c->sub_state = SS_HANDSHAKE;

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof ip);
    snprintf(c->peer, sizeof c->peer, "%s:%u", ip, ntohs(sa->sin_port));

    if (rbuf_grow(c, READ_CHUNK) < 0) { free(c); return NULL; }
    return c;
}

static void client_close(client_t *c);

/* ---------------- subscriber registry (fixed-size array) ---------------- */

#define MAX_SUBS 256
static client_t *g_subs[MAX_SUBS];
static size_t    g_subs_count = 0;

static void subs_add(client_t *c) {
    if (g_subs_count >= MAX_SUBS) {
        LOG_WARN("sub table full; dropping %s", c->peer);
        client_close(c);
        return;
    }
    g_subs[g_subs_count++] = c;
}
static void subs_remove(client_t *c) {
    for (size_t i = 0; i < g_subs_count; i++) {
        if (g_subs[i] == c) {
            g_subs[i] = g_subs[--g_subs_count];
            return;
        }
    }
}

static void client_close(client_t *c) {
    if (c->kind == CK_SUB) subs_remove(c);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    free(c->rbuf);
    for (size_t i = 0; i < c->n_topics; i++) free(c->topics[i]);
    outq_free_all(c);
    LOG_INFO("disconnect %s%s (dropped=%llu)",
             c->kind == CK_PUB ? "PUB " : "SUB ",
             c->peer, (unsigned long long)c->dropped);
    free(c);
}

/* ---------------- topic matching ---------------- */

static int topic_matches(const client_t *c, const char *topic, size_t topic_len) {
    if (c->match_all) return 1;
    for (size_t i = 0; i < c->n_topics; i++) {
        const char *t = c->topics[i];
        size_t tl = strlen(t);
        if (tl == topic_len && memcmp(t, topic, topic_len) == 0) return 1;
        /* prefix wildcard:   "chat.pac.*" matches "chat.pac.<anything>" */
        if (tl >= 2 && t[tl - 1] == '*' && t[tl - 2] == '.' &&
            topic_len >= tl - 1 && memcmp(t, topic, tl - 1) == 0)
            return 1;
    }
    return 0;
}

/* ---------------- SUB handshake ---------------- */

static int send_all_now(int fd, const char *s) {
    size_t len = strlen(s);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, s + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return -1;
    }
    return 0;
}

static int parse_sub_line(client_t *c, char *line, size_t len) {
    /* Strip trailing CR */
    while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == ' ')) len--;
    if (len < 3 || memcmp(line, "SUB", 3) != 0) return -1;
    char *p = line + 3;
    char *end = line + len;
    while (p < end) {
        while (p < end && *p == ' ') p++;
        if (p >= end) break;
        char *tok = p;
        while (p < end && *p != ' ') p++;
        size_t tl = (size_t)(p - tok);
        if (tl == 0) continue;
        if (c->n_topics >= MAX_TOPICS_PER_SUB) return -1;
        char *t = malloc(tl + 1);
        if (!t) return -1;
        memcpy(t, tok, tl);
        t[tl] = '\0';
        if (tl == 2 && t[0] == '*' && t[1] == '*') c->match_all = 1;
        c->topics[c->n_topics++] = t;
    }
    return c->n_topics > 0 ? 0 : -1;
}

static int handle_sub_handshake(client_t *c) {
    /* Look for a newline in the read buffer */
    for (size_t i = 0; i < c->rlen; i++) {
        if (c->rbuf[i] == '\n') {
            char *line = (char *)c->rbuf;
            size_t llen = i;
            int ok = parse_sub_line(c, line, llen) == 0;
            /* Consume the line */
            size_t consumed = i + 1;
            memmove(c->rbuf, c->rbuf + consumed, c->rlen - consumed);
            c->rlen -= consumed;

            if (!ok) {
                send_all_now(c->fd, "ERR bad SUB line\n");
                return -1;
            }
            if (send_all_now(c->fd, "OK\n") < 0) return -1;
            c->sub_state = SS_RUNNING;
            subs_add(c);
            char topics_log[256] = {0};
            size_t off = 0;
            for (size_t k = 0; k < c->n_topics && off < sizeof topics_log - 1; k++) {
                int w = snprintf(topics_log + off, sizeof topics_log - off,
                                 "%s%s", k ? "," : "", c->topics[k]);
                if (w < 0) break;
                off += (size_t)w;
            }
            LOG_INFO("SUB OK %s topics=[%s]%s",
                     c->peer, topics_log, c->match_all ? " (match_all)" : "");
            return 0;
        }
        if (i >= SUB_LINE_MAX) {
            send_all_now(c->fd, "ERR SUB line too long\n");
            return -1;
        }
    }
    if (c->rlen >= SUB_LINE_MAX) {
        send_all_now(c->fd, "ERR SUB line too long\n");
        return -1;
    }
    return 0; /* need more bytes */
}

/* ---------------- fanout ---------------- */

static void fanout(const uint8_t *length_prefixed, size_t total,
                   const char *topic, size_t topic_len) {
    for (size_t i = 0; i < g_subs_count; ) {
        client_t *s = g_subs[i];
        if (s->sub_state != SS_RUNNING) { i++; continue; }
        if (!topic_matches(s, topic, topic_len)) { i++; continue; }
        if (outq_push(s, length_prefixed, total) < 0) {
            LOG_WARN("outq alloc failed for %s; closing", s->peer);
            subs_remove(s);
            client_close(s);
            continue; /* don't increment — array compacted */
        }
        update_epoll_mode(s);
        g_delivered++;
        i++;
    }
}

/* ---------------- PUB frame parsing ---------------- */

/*
 * On each readable PUB event we drain the buffer in a loop, peeling off
 * complete frames (4-byte BE length + payload) and fanning them out.
 */
static int handle_pub_data(client_t *c) {
    for (;;) {
        if (c->rlen < 4) return 0;
        uint32_t net_len;
        memcpy(&net_len, c->rbuf, 4);
        uint32_t flen = ntohl(net_len);
        if (flen == 0 || flen > FRAME_MAX_LEN) {
            LOG_WARN("PUB %s bogus length %u; closing", c->peer, flen);
            return -1;
        }
        if (c->rlen < 4 + flen) {
            if (rbuf_grow(c, 4 + flen) < 0) return -1;
            return 0; /* need more bytes */
        }
        /* zmesg envelope starts at c->rbuf + 4 */
        if (flen < ZMESG_FIXED_HDR) {
            LOG_WARN("PUB %s envelope too short (%u)", c->peer, flen);
            /* still pass it through? no — strict protocol. drop frame. */
        } else {
            uint32_t magic;
            memcpy(&magic, c->rbuf + 4, 4);
            if (magic != ZMESG_MAGIC) {
                LOG_WARN("PUB %s bad magic 0x%08x; closing", c->peer, magic);
                return -1;
            }
            uint16_t topic_len;
            memcpy(&topic_len, c->rbuf + 4 + ZMESG_OFF_TOPIC_LEN, 2);
            if ((uint32_t)ZMESG_FIXED_HDR + topic_len > flen) {
                LOG_WARN("PUB %s topic_len %u exceeds frame %u",
                         c->peer, topic_len, flen);
            } else {
                const char *topic = (const char *)(c->rbuf + 4 + ZMESG_FIXED_HDR);
                /* WAL append before fan-out so durability precedes delivery */
                wal_append(&g_wal, c->rbuf + 4, flen, ORIGIN_TCP);
                /* fan out */
                fanout(c->rbuf, 4 + flen, topic, topic_len);
                g_pub_msgs++;
                g_pub_bytes += flen;
            }
        }
        /* consume frame */
        memmove(c->rbuf, c->rbuf + 4 + flen, c->rlen - (4 + flen));
        c->rlen -= 4 + flen;
    }
}

/* ---------------- UDP datagram pump ---------------- */

static unsigned long long g_udp_msgs = 0;

static void udp_drain(int fd) {
    static uint8_t recv_buf[UDP_RECV_MAX];
    /* Length-prefixed TCP frame staging: 4 + UDP_RECV_MAX. */
    static uint8_t tcp_frame[4 + UDP_RECV_MAX];

    for (;;) {
        struct sockaddr_in sa;
        socklen_t sl = sizeof sa;
        ssize_t n = recvfrom(fd, recv_buf, sizeof recv_buf, 0,
                             (struct sockaddr *)&sa, &sl);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            LOG_WARN("udp recvfrom: %s", strerror(errno));
            return;
        }
        if (n < (ssize_t)ZMESG_FIXED_HDR) {
            LOG_WARN("UDP datagram too short (%zd)", n);
            continue;
        }
        uint32_t magic;
        memcpy(&magic, recv_buf, 4);
        if (magic != ZMESG_MAGIC) {
            LOG_WARN("UDP bad magic 0x%08x", magic);
            continue;
        }
        uint16_t topic_len;
        memcpy(&topic_len, recv_buf + ZMESG_OFF_TOPIC_LEN, 2);
        if ((uint32_t)ZMESG_FIXED_HDR + topic_len > (uint32_t)n) {
            LOG_WARN("UDP topic_len %u exceeds datagram %zd", topic_len, n);
            continue;
        }
        const char *topic = (const char *)(recv_buf + ZMESG_FIXED_HDR);

        wal_append(&g_wal, recv_buf, (size_t)n, ORIGIN_UDP);

        /* Re-frame for TCP fan-out: 4-byte BE length + datagram bytes. */
        uint32_t net_len = htonl((uint32_t)n);
        memcpy(tcp_frame, &net_len, 4);
        memcpy(tcp_frame + 4, recv_buf, (size_t)n);
        fanout(tcp_frame, 4 + (size_t)n, topic, topic_len);

        g_pub_msgs++;
        g_udp_msgs++;
        g_pub_bytes += (uint32_t)n;
    }
}

/* ---------------- read pump ---------------- */

static int client_readable(client_t *c) {
    for (;;) {
        if (rbuf_grow(c, c->rlen + READ_CHUNK) < 0) return -1;
        ssize_t n = read(c->fd, c->rbuf + c->rlen, c->rcap - c->rlen);
        if (n > 0) { c->rlen += (size_t)n; continue; }
        if (n == 0) return -1; /* peer closed */
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        return -1;
    }
    if (c->kind == CK_PUB) {
        return handle_pub_data(c);
    } else {
        if (c->sub_state == SS_HANDSHAKE) {
            return handle_sub_handshake(c);
        }
        /* SUB clients shouldn't send data after handshake; ignore */
        c->rlen = 0;
        return 0;
    }
}

static int client_writable(client_t *c) {
    if (try_flush(c) < 0) return -1;
    update_epoll_mode(c);
    return 0;
}

/* ---------------- accept ---------------- */

static void accept_loop(int listen_fd, client_kind_t kind) {
    for (;;) {
        struct sockaddr_in sa;
        socklen_t sl = sizeof sa;
        int fd = accept4(listen_fd, (struct sockaddr *)&sa, &sl,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            LOG_WARN("accept: %s", strerror(errno));
            return;
        }
        set_nodelay(fd);
        client_t *c = client_new(fd, kind, &sa);
        if (!c) { close(fd); continue; }

        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = c };
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            LOG_ERR("epoll_ctl ADD: %s", strerror(errno));
            close(fd);
            free(c->rbuf);
            free(c);
            continue;
        }
        c->want_write = EPOLLIN;
        LOG_INFO("connect %s%s", kind == CK_PUB ? "PUB " : "SUB ", c->peer);
    }
}

/* ---------------- main ---------------- */

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    const char *wal_dir = getenv("WAL_DIR");
    if (!wal_dir || !*wal_dir) wal_dir = WAL_DIR_DEFAULT;
    if (wal_init(&g_wal, wal_dir) < 0) {
        LOG_WARN("WAL init failed; continuing without durability");
    }

    int pub_fd = listen_tcp(PUB_PORT);
    int sub_fd = listen_tcp(SUB_PORT);
    int udp_fd = bind_udp(UDP_PORT);
    if (pub_fd < 0 || sub_fd < 0 || udp_fd < 0) return 1;

    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) { LOG_ERR("epoll_create1: %s", strerror(errno)); return 1; }

    static ev_handle_t pub_ev = { EV_LISTEN_PUB };
    static ev_handle_t sub_ev = { EV_LISTEN_SUB };
    static ev_handle_t udp_ev = { EV_LISTEN_UDP };
    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.ptr = &pub_ev;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, pub_fd, &ev);
    ev.events = EPOLLIN; ev.data.ptr = &sub_ev;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sub_fd, &ev);
    ev.events = EPOLLIN; ev.data.ptr = &udp_ev;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev);

    LOG_INFO("planetar-broker phase-3 ready · PUB=%d SUB=%d UDP=%d · WAL=%s seq=%llu",
             PUB_PORT, SUB_PORT, UDP_PORT, g_wal.enabled ? wal_dir : "off",
             (unsigned long long)g_sequence);

    struct epoll_event events[EPOLL_BATCH];
    while (!g_stop) {
        int n = epoll_wait(g_epoll_fd, events, EPOLL_BATCH, 1000);
        if (n < 0) { if (errno == EINTR) continue; LOG_ERR("epoll_wait: %s", strerror(errno)); break; }
        for (int i = 0; i < n; i++) {
            ev_handle_t *h = events[i].data.ptr;
            if (h->kind == EV_LISTEN_PUB) { accept_loop(pub_fd, CK_PUB); continue; }
            if (h->kind == EV_LISTEN_SUB) { accept_loop(sub_fd, CK_SUB); continue; }
            if (h->kind == EV_LISTEN_UDP) { udp_drain(udp_fd); continue; }
            client_t *c = (client_t *)h;
            int rc = 0;
            if (events[i].events & (EPOLLERR | EPOLLHUP)) rc = -1;
            if (rc == 0 && (events[i].events & EPOLLIN))  rc = client_readable(c);
            if (rc == 0 && (events[i].events & EPOLLOUT)) rc = client_writable(c);
            if (rc < 0) client_close(c);
        }
    }

    LOG_INFO("shutting down. pub_msgs=%llu (tcp=%llu udp=%llu) pub_bytes=%llu delivered=%llu seq=%llu",
             g_pub_msgs, g_pub_msgs - g_udp_msgs, g_udp_msgs,
             g_pub_bytes, g_delivered, (unsigned long long)g_sequence);
    wal_close(&g_wal);
    /* best-effort cleanup */
    for (size_t i = 0; i < g_subs_count; i++) client_close(g_subs[i]);
    close(pub_fd);
    close(sub_fd);
    close(udp_fd);
    close(g_epoll_fd);
    return 0;
}
