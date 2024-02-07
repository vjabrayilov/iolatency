#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// #include "bits.bpf.h"
// #include "core_fixes.bpf.h"

#define MAX_ENTRIES 10240

#define DISK_NAME_LEN 32
#define MAX_SLOTS 27

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;
const volatile bool targ_single = true;

struct hist_key {
  __u32 cmd_flags;
  __u32 dev;
};

struct hist {
  __u32 slots[MAX_SLOTS];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct request *);
  __type(value, u64);
} start SEC(".maps");

static struct hist initial_hist;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct hist_key);
  __type(value, struct hist);
} hists SEC(".maps");

static __always_inline u64 log2(u32 v) {
  u32 shift, r;

  r = (v > 0xFFFF) << 4;
  v >>= r;
  shift = (v > 0xFF) << 3;
  v >>= shift;
  r |= shift;
  shift = (v > 0xF) << 2;
  v >>= shift;
  r |= shift;
  shift = (v > 0x3) << 1;
  v >>= shift;
  r |= shift;
  r |= (v >> 1);

  return r;
}

static __always_inline u64 log2l(u64 v) {
  u32 hi = v >> 32;

  if (hi)
    return log2(hi) + 32;
  else
    return log2(v);
}

static int __always_inline trace_rq_start(struct request *rq, int issue) {
  u64 ts;

  ts = bpf_ktime_get_ns();

  bpf_map_update_elem(&start, &rq, &ts, 0);
  return 0;
}

static int handle_block_rq_insert(__u64 *ctx) {
  /**
   * commit a54895fa (v5.11-rc1) changed tracepoint argument list
   * from TP_PROTO(struct request_queue *q, struct request *rq)
   * to TP_PROTO(struct request *rq)
   */
  // if (!targ_single)
  // return trace_rq_start((void *)ctx[1], false);
  // else
  return trace_rq_start((void *)ctx[0], false);
}

static int handle_block_rq_issue(__u64 *ctx) {
  /**
   * commit a54895fa (v5.11-rc1) changed tracepoint argument list
   * from TP_PROTO(struct request_queue *q, struct request *rq)
   * to TP_PROTO(struct request *rq)
   */
  // if (!targ_single)
  // return trace_rq_start((void *)ctx[1], true);
  // else
  return trace_rq_start((void *)ctx[0], true);
}

static int handle_block_rq_complete(struct request *rq, int error,
                                    unsigned int nr_bytes) {
  u64 slot, *tsp, ts = bpf_ktime_get_ns();
  struct hist_key hkey = {};
  struct hist *histp;
  s64 delta;

  tsp = bpf_map_lookup_elem(&start, &rq);
  if (!tsp)
    return 0;

  delta = (s64)(ts - *tsp);
  if (delta < 0)
    goto cleanup;

  histp = bpf_map_lookup_elem(&hists, &hkey);
  if (!histp) {
    bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
    histp = bpf_map_lookup_elem(&hists, &hkey);
    if (!histp)
      goto cleanup;
  }

  delta /= 1000U;
  slot = log2l(delta);
  if (slot >= MAX_SLOTS)
    slot = MAX_SLOTS - 1;
  __sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
  bpf_map_delete_elem(&start, &rq);
  return 0;
}

// SEC("tp_btf/block_rq_insert")
// int block_rq_insert_btf(u64 *ctx) { return handle_block_rq_insert(ctx); }

// SEC("tp_btf/block_rq_issue")
// int block_rq_issue_btf(u64 *ctx) { return handle_block_rq_issue(ctx); }

// SEC("tp_btf/block_rq_complete")
// int BPF_PROG(block_rq_complete_btf, struct request *rq, int error,
//              unsigned int nr_bytes) {
//   return handle_block_rq_complete(rq, error, nr_bytes);
// }

SEC("raw_tp/block_rq_insert")
int BPF_PROG(block_rq_insert) { return handle_block_rq_insert(ctx); }

SEC("raw_tp/block_rq_issue")
int BPF_PROG(block_rq_issue) { return handle_block_rq_issue(ctx); }

SEC("raw_tp/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error,
             unsigned int nr_bytes) {
  return handle_block_rq_complete(rq, error, nr_bytes);
}

char LICENSE[] SEC("license") = "GPL";