#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// https://lwn.net/Articles/1036604/
// I took those constants from https://eunomia.dev/tutorials/6-sigsnoop/
#define MAX_ENTRIES     10240
#define TASK_COMM_LEN   16

#define GB              1073741824
#define _10MB           10485760

#define CLONE_THREAD	0x00010000

#define HASH_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __uint(max_entries, MAX_ENTRIES); \
    __type(key, __u64); \
    __type(value, __u64); \
} name SEC(".maps")


char LICENSE[] SEC("license") = "GPL";

extern int bpf_strstr(const char *s1, const char *s2) __ksym;
extern int __preempt_count __ksym;
extern int bpf_in_interrupt __ksym;


int filter_comm();

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} meminfo_map SEC(".maps");

SEC("kprobe/si_meminfo")
int handle_si_meminfo(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;
    
    if (bpf_strstr(comm, "loader.user") < 0)
        return 0;

    struct sysinfo *info = (struct sysinfo *)PT_REGS_PARM1(ctx);

    __u32 zero = 0;
    __u64 ptr = (__u64)info;
    bpf_map_update_elem(&meminfo_map, &zero, &ptr, BPF_ANY);

    return 0;
}

SEC("kretprobe/si_meminfo")
int handle_exit_si_meminfo(void *ctx) {
    char comm[TASK_COMM_LEN];
    
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;
    
    if (bpf_strstr(comm, "loader.user") < 0)
        return 0;

    __u32 zero = 0;
    __u32 one = 1;

    __u64 *ptr = bpf_map_lookup_elem(&meminfo_map, &zero);
    if (!ptr)
        return 0;

    struct sysinfo *info = (struct sysinfo*)*ptr;

    if (info) {
        __u64 mem = (BPF_CORE_READ(info, totalram) - BPF_CORE_READ(info, freeram)) * BPF_CORE_READ(info, mem_unit);
        // bpf_printk("used memory: %llu\n", mem);
        if (mem >= GB) {
            bpf_map_update_elem(&meminfo_map, &one, &one, BPF_ANY);
        } else {
            bpf_map_update_elem(&meminfo_map, &one, &zero, BPF_ANY);
        }
    }

    return 0;
}


int check_memory() {
    __u32 one = 1;
    __u64 *ptr = bpf_map_lookup_elem(&meminfo_map, &one);
    if (ptr)
        return *ptr == 1;
    return 0;
}

void update_value(void *map, const void *key, __u64 addi, __u64 threshold) {
    __u64 *val = bpf_map_lookup_elem(map, key);

    if (val) {
        __sync_fetch_and_add(val, addi);
    } else {
        if (bpf_map_update_elem(map, key, &addi, BPF_NOEXIST) != 0) {
            val = bpf_map_lookup_elem(map, key);
            if (val)
                __sync_fetch_and_add(val, addi);
        }
    }

    val = bpf_map_lookup_elem(map, key);
    if (val) {
        // bpf_printk("val: %llu\n", *val);

        if (check_memory()) {
            if (*val >= threshold)
                bpf_send_signal(9);
        }
    }
}


HASH_MAP(fd_map);

SEC("kprobe/fd_install")
int handle_new_fd(void *ctx) {
    if (filter_comm())
        return 0;
    
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    update_value(&fd_map, &pid, 1, 100);

    return 0;
}


HASH_MAP(clone_map);

SEC("kprobe/kernel_clone")
int handle_enter_clone3(struct pt_regs *ctx) {
    if (filter_comm())
        return 0;
    
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct kernel_clone_args *args = (struct kernel_clone_args *)PT_REGS_PARM1(ctx);
    
    if (BPF_CORE_READ(args, flags) & CLONE_THREAD)
        update_value(&clone_map, &pid, 1, 100);

    return 0;
}


HASH_MAP(write_map);

struct sys_exit_write_args {
    char unused[8];
    int syscall_nr;
    long ret;
};

// https://eunomia.dev/tutorials/2-kprobe-unlink/#kprobe-example
SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(handlvfs_write_exit, long ret){
    if (filter_comm())
        return 0;
    
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    // bpf_printk("ret: %ld\n", ret);
    if (ret >= 0)
        update_value(&write_map, &pid, 1, 100);

    return 0;
}

HASH_MAP(read_map);

struct sys_exit_read_args {
    char unused[8];
    int syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct sys_exit_read_args *ctx) {
    if (filter_comm())
        return 0;
    
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (ctx->ret >= 0)
        update_value(&read_map, &pid, ctx->ret, _10MB);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int handle_readv_exit(struct sys_exit_read_args *ctx) {
    if (filter_comm())
        return 0;
    
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (ctx->ret >= 0) {
        bpf_printk("READV: %d\n", ctx->ret);
        update_value(&read_map, &pid, ctx->ret, _10MB);
    }

    return 0;
}

HASH_MAP(rand_map);

SEC("uprobe//usr/lib/x86_64-linux-gnu/libc.so.6:rand")
int rand(struct pt_regs *ctx) {
    if (filter_comm())
        return 0;

    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    update_value(&rand_map, &pid, 1, 100);

    return 0;
}

int filter_comm() {
    char comm[TASK_COMM_LEN];

    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return -1;

    if (bpf_strstr(comm, "oomp") < 0)
        return -1;   

    return 0;
}

SEC("kprobe/ip_output")
int handle_ip_output(struct pt_regs *ctx)

#define ___bpf_mvb(x, b, n, m) ((__u##b)(x) << (b-(n+1)*8) >> (b-8) << (m*8))

#define ___bpf_swab16(x) ((__u16)(          \
              ___bpf_mvb(x, 16, 0, 1) | \
              ___bpf_mvb(x, 16, 1, 0)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)         __builtin_bswap16(x)
# define __bpf_constant_ntohs(x)    ___bpf_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)         (x)
# define __bpf_constant_ntohs(x) #include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/* Minimal TCP header (20 bytes, no options) */
struct tcphdr_min {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res;  /* data offset (4 bits) + reserved (4 bits) */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

/* Pseudo-header for TCP checksum over IPv4 */
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

static uint16_t checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *p = data;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)p;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int main()
{    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        perror("socket(SOCK_RAW)");
        return 1;
    }

    /* We build the IP header ourselves (IPPROTO_RAW implies IP_HDRINCL) */
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    uint16_t src_port = htons(44444);
    uint16_t dst_port = htons(55555);

    for (int i = 0; i < 2000; i++) {
        char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr_min)] = {0};
        struct iphdr *ip       = (struct iphdr *)pkt;
        struct tcphdr_min *tcp = (struct tcphdr_min *)(pkt + sizeof(struct iphdr));

        /* IP header */
        ip->ihl     = 5;
        ip->version = 4;
        ip->tot_len = htons(sizeof(pkt));
        ip->id      = htons(54321 + i);
        ip->ttl     = 64;
        ip->protocol = 6;  /* IPPROTO_TCP */
        ip->saddr   = htonl(INADDR_LOOPBACK);
        ip->daddr   = htonl(INADDR_LOOPBACK);
        ip->check   = 0;
        ip->check   = checksum(ip, sizeof(struct iphdr));

        /* TCP header */
        tcp->src_port = src_port;
        tcp->dst_port = dst_port;
        tcp->seq      = htonl(1000 + i);
        tcp->ack_seq  = 0;
        tcp->doff_res = (5 << 4);  /* data offset = 5 words (20 bytes) */
        tcp->flags    = 0x02;      /* SYN */
        tcp->window   = htons(65535);
        tcp->checksum = 0;
        tcp->urg_ptr  = 0;

        /* TCP checksum (with pseudo-header) */
        struct pseudo_hdr ph = {
            .src     = ip->saddr,
            .dst     = ip->daddr,
            .zero    = 0,
            .proto   = 6,
            .tcp_len = htons(sizeof(struct tcphdr_min)),
        };
        char csum_buf[sizeof(ph) + sizeof(struct tcphdr_min)];
        memcpy(csum_buf, &ph, sizeof(ph));
        memcpy(csum_buf + sizeof(ph), tcp, sizeof(struct tcphdr_min));
        tcp->checksum = checksum(csum_buf, sizeof(csum_buf));

        ssize_t ret = sendto(sock, pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&dst_addr, sizeof(dst_addr));
        if (ret == -1) {
            perror("sendto");
            close(sock);
            return 1;
        }
        break;
    }


    /* Stay alive so monitor can inspect stats */
    for (;;) pause();
    return 0;
}

I want to investigate code of this TCP and also code of classical TCP program doing send
how these two sendto "meet", where is the moment in the kernel where its knmown already that this sendto is TCP   (x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_ntohs(x)                \
    (__builtin_constant_p(x) ?      \
     __bpf_constant_ntohs(x) : __bpf_ntohs(x))

#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define SOFTIRQ_OFFSET		(1 << 8)
#define SOFTIRQ_MASK		(0xF << 8)

SEC("kprobe/ip_output")
int handle_ip_output(struct pt_regs *ctx)
{
    if(filter_comm())
        return 0;

    // bpf_printk("hello\n");
    // bpf_in_interrupt(&__preempt_count);

    /* Filter out softirq context - check if current task is actually
     * performing a syscall (not handling a softirq on behalf of it).
     * In softirq context on x86, in_task() == false.
     * We check via the per-CPU __preempt_count ksym. */
    // int pcount = *(int *)bpf_this_cpu_ptr(&__preempt_count);
    // if (pcount & SOFTIRQ_MASK)
    //     return 0;
    
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);

    struct iphdr *iph;
    struct iphdr iph_copy;
    
    iph = BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
    bpf_probe_read_kernel(&iph_copy, sizeof(iph_copy), iph);

    if (iph_copy.protocol != IPPROTO_TCP)
        return 0;  

    struct tcphdr *th;
    struct tcphdr th_copy;
    
    th = BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header);
    bpf_probe_read_kernel(&th_copy, sizeof(th_copy), th);

    u16 sport = bpf_ntohs(th_copy.source);
    u16 dport = bpf_ntohs(th_copy.dest);

    u16 sport = th_copy.source;
    u16 dport = th_copy.dest;

    bpf_printk("ip_output: %d->%d syn=%d rst=%d ack=%d\n",
               sport, dport,
               th_copy.syn, th_copy.rst, th_copy.ack);

    return 0;
}