// ssh_ip_tracker.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// リモートIP（IPv4）ごとのSSH接続カウンタ
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // リモートIPアドレス
    __type(value, __u64);  // 接続カウント
} ssh_ip_count SEC(".maps");

// カウンタの更新を行うヘルパー関数
static __always_inline void update_counter(__u32 ip, int delta) {
    __u64 *val = bpf_map_lookup_elem(&ssh_ip_count, &ip);
    if (val) {
        if (delta > 0) {
            __sync_fetch_and_add(val, delta);
        } else {
            // カウンタが0より大きい場合のみデクリメント
            if (*val > 0)
                __sync_fetch_and_sub(val, -delta);
        }
    } else if (delta > 0) {
        __u64 init_val = delta;
        bpf_map_update_elem(&ssh_ip_count, &ip, &init_val, BPF_ANY);
    }
}

SEC("xdp")
int xdp_ssh_alert(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernetヘッダの検証
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // IPヘッダの検証
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // TCPヘッダの検証
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // SSH宛先ポート（22番）のパケットのみ処理
    if (tcp->dest != __constant_htons(22))
        return XDP_PASS;

    // クライアントからの初回SYNで接続開始を判定
    if (tcp->syn && !tcp->ack) {
        update_counter(ip->saddr, 1);
        bpf_printk("SSH connection from %x detected\n", ip->saddr);
    }
    // FINまたはRSTで接続終了を判定
    else if (tcp->fin || tcp->rst) {
        update_counter(ip->saddr, -1);
        bpf_printk("SSH connection termination from %x detected\n", ip->saddr);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
