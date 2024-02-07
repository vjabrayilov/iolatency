#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define MAX_SLOTS 27

struct hist_key {
  __u32 cmd_flags;
  __u32 dev;
};

struct hist {
  __u32 slots[MAX_SLOTS];
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static volatile bool exiting;

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

int main(int argc, char **argv) {
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;
  int prog_fd;

  struct tm *tm;
  char ts[32];
  time_t t;
  int err;
  int idx, cg_map_fd;
  int cgfd = -1;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <seconds>\n", argv[0]);
    return 1;
  }

  // Convert argument to integer
  char *endptr;
  long interval = strtol(argv[1], &endptr, 10);

  // Check for conversion errors (no digits found, or not the entire string was
  // consumed)
  if (endptr == argv[1] || *endptr != '\0') {
    fprintf(stderr, "Invalid input: %s is not an integer.\n", argv[1]);
    return 1;
  }

  // Check for negative values
  if (interval < 0) {
    fprintf(stderr, "Invalid input: time cannot be negative.\n");
    return 1;
  }

  // Load and verify BPF application
  fprintf(stderr, "Loading BPF code in memory\n");
  obj = bpf_object__open_file("iolatency.bpf.o", NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return 1;
  }

  // Attach BPF program
  fprintf(stderr, "Attaching BPF program to tracepoint\n");
  prog = bpf_object__find_program_by_name(obj, "syscount");
  if (libbpf_get_error(prog)) {
    fprintf(stderr, "ERROR: finding BPF program failed\n");
    return 1;
  }
  prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "ERROR: getting BPF program FD failed\n");
    return 1;
  }
  // Load BPF program
  fprintf(stderr, "Loading and verifying the code in the kernel\n");
  if (bpf_object__load(obj)) {
    fprintf(stderr, "ERROR: loading BPF object file failed\n");
    return 1;
  }

  // Attach
  const char *tracepoints[] = {"block_rq_insert", "block_rq_issue",
                               "block_rq_complete"};

  for (size_t i = 0; i < sizeof(tracepoints) / sizeof(tracepoints[0]); ++i) {

    link = bpf_program__attach_tracepoint(prog, "block", tracepoints[i]);
    if (libbpf_get_error(link)) {
      fprintf(stderr, "ERROR: Attaching BPF program to tracepoint %s failed\n",
              tracepoints[i]);
      return 1;
    }
  }

  signal(SIGINT, sig_handler);

  printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

  /* main: poll */
  while (1) {
    sleep(interval);
    // TODO: fix map and pass to the function below
    err = print_log2_hists(obj->maps.hist);
    if (err)
      break;

    if (exiting)
      break;
  }

  return 0;
}