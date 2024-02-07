#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define DISK_NAME_LEN 32
#define MAX_SLOTS 27

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

struct hist_key {
  __u32 cmd_flags;
  __u32 dev;
};

struct hist {
  __u32 slots[MAX_SLOTS];
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static volatile bool exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG && !env.verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) { exiting = true; }

static int print_log2_hists(struct bpf_map *hists,
                            struct partitions *partitions) {
  struct hist_key lookup_key = {.cmd_flags = -1}, next_key;
  const char *units = env.milliseconds ? "msecs" : "usecs";
  const struct partition *partition;
  int err, fd = bpf_map__fd(hists);
  struct hist hist;

  while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    err = bpf_map_lookup_elem(fd, &next_key, &hist);
    if (err < 0) {
      fprintf(stderr, "failed to lookup hist: %d\n", err);
      return -1;
    }
    if (env.per_disk) {
      partition = partitions__get_by_dev(partitions, next_key.dev);
      printf("\ndisk = %s\t", partition ? partition->name : "Unknown");
    }
    if (env.per_flag)
      print_cmd_flags(next_key.cmd_flags);
    printf("\n");
    print_log2_hist(hist.slots, MAX_SLOTS, units);
    lookup_key = next_key;
  }

  lookup_key.cmd_flags = -1;
  while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    err = bpf_map_delete_elem(fd, &next_key);
    if (err < 0) {
      fprintf(stderr, "failed to cleanup hist : %d\n", err);
      return -1;
    }
    lookup_key = next_key;
  }

  return 0;
}

/*
 * BTF has a func proto for each tracepoint, let's check it like
 *   typedef void (*btf_trace_block_rq_issue)(void *, struct request *);
 *
 * Actually it's a typedef for a pointer to the func proto.
 */
static bool has_block_rq_issue_single_arg(void) {
  const struct btf *btf = btf__load_vmlinux_btf();
  const struct btf_type *t1, *t2, *t3;
  __u32 type_id;
  bool ret = true; // assuming recent kernels

  type_id =
      btf__find_by_name_kind(btf, "btf_trace_block_rq_issue", BTF_KIND_TYPEDEF);
  if ((__s32)type_id < 0)
    return ret;

  t1 = btf__type_by_id(btf, type_id);
  if (t1 == NULL)
    return ret;

  t2 = btf__type_by_id(btf, t1->type);
  if (t2 == NULL || !btf_is_ptr(t2))
    return ret;

  t3 = btf__type_by_id(btf, t2->type);
  if (t3 && btf_is_func_proto(t3))
    ret = (btf_vlen(t3) == 2); // ctx + arg

  return ret;
}

int main(int argc, char **argv) {
  struct biolatency_bpf *obj;
  struct tm *tm;
  char ts[32];
  time_t t;
  int err;
  int idx, cg_map_fd;
  int cgfd = -1;


  libbpf_set_print(libbpf_print_fn);

  obj = iolatency_bpf__open();
  if (!obj) {
    fprintf(stderr, "failed to open BPF object\n");
    return 1;
  }

  if (probe_tp_btf("block_rq_insert")) {
    bpf_program__set_autoload(obj->progs.block_rq_insert, false);
    bpf_program__set_autoload(obj->progs.block_rq_issue, false);
    bpf_program__set_autoload(obj->progs.block_rq_complete, false);
    if (!env.queued)
      bpf_program__set_autoload(obj->progs.block_rq_insert_btf, false);
  } else {
    bpf_program__set_autoload(obj->progs.block_rq_insert_btf, false);
    bpf_program__set_autoload(obj->progs.block_rq_issue_btf, false);
    bpf_program__set_autoload(obj->progs.block_rq_complete_btf, false);
    if (!env.queued)
      bpf_program__set_autoload(obj->progs.block_rq_insert, false);
  }

  err = iolatency_bpf__load(obj);
  if (err) {
    fprintf(stderr, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }

  err = iolatency_bpf__attach(obj);
  if (err) {
    fprintf(stderr, "failed to attach BPF object: %d\n", err);
    goto cleanup;
  }

  signal(SIGINT, sig_handler);

  printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

  /* main: poll */
  while (1) {
    sleep(env.interval);
    printf("\n");

    if (env.timestamp) {
      time(&t);
      tm = localtime(&t);
      strftime(ts, sizeof(ts), "%H:%M:%S", tm);
      printf("%-8s\n", ts);
    }

    err = print_log2_hists(obj->maps.hists, partitions);
    if (err)
      break;

    if (exiting || --env.times == 0)
      break;
  }

cleanup:
  iolatency_bpf__destroy(obj);
  partitions__free(partitions);
  if (cgfd > 0)
    close(cgfd);

  return err != 0;
}