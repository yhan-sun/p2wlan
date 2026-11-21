/* Test-only UDP egress interception. No production binary is linked to this.
 * Preserve the original socket/source port and report the destination even
 * when nobody has bound that destination. Only IPv4 loopback UDP is eligible;
 * TCP, non-loopback traffic, receives and the simulator itself are untouched.
 * The production Tokio UDP path uses sendto; sendmsg is covered as well.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define HEADER_SIZE 16
#define MAX_PAYLOAD (65507 - HEADER_SIZE)
static pthread_once_t initialize_once = PTHREAD_ONCE_INIT;
static struct sockaddr_in gateway;
static int enabled;
struct egress_stats {
    char magic[8];
    _Atomic uint64_t packets;
    _Atomic uint64_t bytes;
    _Atomic uint64_t errors;
    uint64_t gateway_port;
};
static struct egress_stats *stats;
#ifndef __APPLE__
static ssize_t (*original_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*original_sendmsg)(int, const struct msghdr *, int);
#endif

static void initialize(void) {
#ifndef __APPLE__
    *(void **)(&original_sendto) = dlsym(RTLD_NEXT, "sendto");
    *(void **)(&original_sendmsg) = dlsym(RTLD_NEXT, "sendmsg");
#endif
    const char *port_text = getenv("P2WLAN_NAT_SIM_GATEWAY_PORT");
    if (!port_text || !*port_text) return;
    char *end;
    long port = strtol(port_text, &end, 10);
    if (*end || port < 1 || port > 65535) return;
    gateway.sin_family = AF_INET;
#ifdef __APPLE__
    gateway.sin_len = sizeof(gateway);
#endif
    gateway.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    gateway.sin_port = htons((uint16_t)port);
    enabled = 1;
    /* A shared file survives signals, including SIGKILL. The harness compares
     * these successful-send counters with gateway receipts after both daemons
     * stop, rejecting local UDP loss instead of silently missing allocations. */
    const char *stats_path = getenv("P2WLAN_NAT_SIM_EGRESS_STATS");
    if (stats_path && *stats_path) {
        int fd = open(stats_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) { enabled = -1; return; }
        if (ftruncate(fd, sizeof(struct egress_stats))) {
            close(fd); enabled = -1; return;
        }
        void *mapped = mmap(NULL, sizeof(struct egress_stats), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        if (mapped == MAP_FAILED) { enabled = -1; return; }
        stats = mapped;
        memcpy(stats->magic, "P2CNT001", 8);
        atomic_init(&stats->packets, 0);
        atomic_init(&stats->bytes, 0);
        atomic_init(&stats->errors, 0);
        stats->gateway_port = (uint64_t)port;
    }
}

static int eligible(int fd, const struct sockaddr *destination, socklen_t length) {
    pthread_once(&initialize_once, initialize);
    if (!enabled || !destination || length < sizeof(struct sockaddr_in) ||
        destination->sa_family != AF_INET) return 0;
    const struct sockaddr_in *address = (const struct sockaddr_in *)destination;
    if ((ntohl(address->sin_addr.s_addr) >> 24) != 127) return 0;
    int kind = 0;
    socklen_t kind_length = sizeof(kind);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &kind_length) == 0 && kind == SOCK_DGRAM;
}

static ssize_t real_sendto(int fd, const void *data, size_t length, int flags,
                           const struct sockaddr *destination, socklen_t destination_length) {
#ifdef __APPLE__
    return sendto(fd, data, length, flags, destination, destination_length);
#else
    if (!original_sendto) { errno = ENOSYS; return -1; }
    return original_sendto(fd, data, length, flags, destination, destination_length);
#endif
}

static ssize_t real_sendmsg(int fd, const struct msghdr *message, int flags) {
#ifdef __APPLE__
    return sendmsg(fd, message, flags);
#else
    if (!original_sendmsg) { errno = ENOSYS; return -1; }
    return original_sendmsg(fd, message, flags);
#endif
}

static void encode_header(unsigned char *header, const struct sockaddr *destination,
                          size_t length) {
    const struct sockaddr_in *address = (const struct sockaddr_in *)destination;
    memcpy(header, "P2NAT001", 8);
    memcpy(header + 8, &address->sin_addr.s_addr, 4);
    memcpy(header + 12, &address->sin_port, 2);
    uint16_t wire_length = htons((uint16_t)length);
    memcpy(header + 14, &wire_length, 2);
}

static ssize_t account_handoff(ssize_t sent, size_t length) {
    if (sent < 0) {
        if (stats) atomic_fetch_add_explicit(&stats->errors, 1, memory_order_relaxed);
        return sent;
    }
    if ((size_t)sent != length + HEADER_SIZE) { errno = EIO; return -1; }
    if (stats) {
        atomic_fetch_add_explicit(&stats->packets, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&stats->bytes, length, memory_order_relaxed);
    }
    return (ssize_t)length;
}

static ssize_t wrapped_sendto(int fd, const void *data, size_t length, int flags,
                              const struct sockaddr *destination, socklen_t destination_length) {
    int saved_errno = errno;
    if (!eligible(fd, destination, destination_length)) {
        errno = saved_errno;
        return real_sendto(fd, data, length, flags, destination, destination_length);
    }
    if (enabled < 0) { errno = EIO; return -1; }
    if (length > MAX_PAYLOAD) { errno = EMSGSIZE; return -1; }
    if (length && !data) { errno = EFAULT; return -1; }
    /* Keep packet-sized data off the caller's stack. The two buffers remain
     * borrowed only during this synchronous original kernel handoff. */
    unsigned char header[HEADER_SIZE];
    encode_header(header, destination, length);
    struct iovec parts[] = {{header, sizeof(header)}, {(void *)data, length}};
    struct msghdr message = {0};
    message.msg_name = &gateway;
    message.msg_namelen = sizeof(gateway);
    message.msg_iov = parts;
    message.msg_iovlen = 2;
    return account_handoff(real_sendmsg(fd, &message, flags), length);
}

static ssize_t wrapped_sendmsg(int fd, const struct msghdr *message, int flags) {
    int saved_errno = errno;
    if (!message || !eligible(fd, message->msg_name, message->msg_namelen)) {
        pthread_once(&initialize_once, initialize);
        errno = saved_errno;
        return real_sendmsg(fd, message, flags);
    }
    /* Ancillary routing controls are not part of this loopback harness. */
    if (message->msg_controllen) { errno = EOPNOTSUPP; return -1; }
    if (message->msg_iovlen && !message->msg_iov) { errno = EFAULT; return -1; }
    size_t length = 0;
    for (size_t index = 0; index < (size_t)message->msg_iovlen; index++) {
        size_t count = message->msg_iov[index].iov_len;
        if (count > MAX_PAYLOAD - length) { errno = EMSGSIZE; return -1; }
        if (count && !message->msg_iov[index].iov_base) { errno = EFAULT; return -1; }
        length += count;
    }
    if (enabled < 0) { errno = EIO; return -1; }
    /* Flatten at most one UDP frame, preserving the old accepted iovec count
     * without a packet-sized stack frame or a retained per-thread buffer. */
    unsigned char *frame = malloc(HEADER_SIZE + length);
    if (!frame) { errno = ENOMEM; return -1; }
    encode_header(frame, message->msg_name, length);
    size_t offset = HEADER_SIZE;
    for (size_t index = 0; index < (size_t)message->msg_iovlen; index++) {
        size_t count = message->msg_iov[index].iov_len;
        if (count) memcpy(frame + offset, message->msg_iov[index].iov_base, count);
        offset += count;
    }
    ssize_t sent = account_handoff(real_sendto(fd, frame, HEADER_SIZE + length, flags,
                                  (const struct sockaddr *)&gateway, sizeof(gateway)), length);
    int send_errno = errno;
    free(frame);
    errno = send_errno;
    return sent;
}

#ifdef __APPLE__
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)wrapped_sendto, (const void *)sendto},
    {(const void *)wrapped_sendmsg, (const void *)sendmsg},
};
#else
ssize_t sendto(int fd, const void *data, size_t length, int flags,
               const struct sockaddr *destination, socklen_t destination_length) {
    return wrapped_sendto(fd, data, length, flags, destination, destination_length);
}
ssize_t sendmsg(int fd, const struct msghdr *message, int flags) {
    return wrapped_sendmsg(fd, message, flags);
}
#endif
