#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define min(x, y)                                                              \
  ({                                                                           \
    typeof(x) _min1 = (x);                                                     \
    typeof(y) _min2 = (y);                                                     \
    (void)(&_min1 == &_min2);                                                  \
    _min1 < _min2 ? _min1 : _min2;                                             \
  })
static volatile bool exiting;

static void print_stars(unsigned int val, unsigned int val_max, int width) {
  int num_stars, num_spaces, i;
  bool need_plus;

  num_stars = min(val, val_max) * width / val_max;
  num_spaces = width - num_stars;
  need_plus = val > val_max;

  for (i = 0; i < num_stars; i++)
    printf("*");
  for (i = 0; i < num_spaces; i++)
    printf(" ");
  if (need_plus)
    printf("+");
}
void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type) {
  int stars_max = 40, idx_max = -1;
  unsigned int val, val_max = 0;
  unsigned long long low, high;
  int stars, width, i;

  for (i = 0; i < vals_size; i++) {
    val = vals[i];
    if (val > 0)
      idx_max = i;
    if (val > val_max)
      val_max = val;
  }

  if (idx_max < 0)
    return;

  printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
         idx_max <= 32 ? 19 : 29, val_type);

  if (idx_max <= 32)
    stars = stars_max;
  else
    stars = stars_max / 2;

  for (i = 0; i <= idx_max; i++) {
    low = (1ULL << (i + 1)) >> 1;
    high = (1ULL << (i + 1)) - 1;
    if (low == high)
      low -= 1;
    val = vals[i];
    width = idx_max <= 32 ? 10 : 20;
    printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
    print_stars(val, val_max, stars);
    printf("|\n");
  }
}
static void sig_handler(int sig) { exiting = true; }

static int print_log2_hists(struct bpf_map *hists) {
  struct hist_key lookup_key = {.cmd_flags = -1}, next_key;
  const char *units = "usecs";
  int err, fd = bpf_map__fd(hists);
  struct hist hist;

  while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    err = bpf_map_lookup_elem(fd, &next_key, &hist);
    if (err < 0) {
      fprintf(stderr, "failed to lookup hist: %d\n", err);
      return -1;
    }
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
  int prog_fd;
  int err;

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
  if (!obj) { // libbpf_get_error(obj)) {
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return 1;
  }

  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "ERROR: Failed to load eBPF program: %s\n", strerror(-err));
    bpf_object__close(obj);
    return 1;
  }

  bpf_object__for_each_program(prog, obj) {
    const char *tp_name = bpf_program__name(prog);
    prog_fd = bpf_raw_tracepoint_open(tp_name, bpf_program__fd(prog));
    if (prog_fd < 0) {
      fprintf(stderr,
              "ERROR: Failed to attach eBPF program to tracepoint %s: %s\n",
              tp_name, strerror(errno));
      bpf_object__close(obj);
      return 1;
    }
  }
  // const char *tracepoints[] = {"block_rq_insert", "block_rq_issue",
  //                              "block_rq_complete"};

  // for (size_t i = 0; i < 3; i++) {
  //   // Attach BPF program
  //   fprintf(stderr, "Attaching BPF program to tracepoint\n");
  //   prog = bpf_object__find_program_by_name(obj, tracepoints[i]);
  //   if (libbpf_get_error(prog)) {
  //     fprintf(stderr, "ERROR: finding BPF program failed\n");
  //     return 1;
  //   }
  //   prog_fd = bpf_program__fd(prog);
  //   if (prog_fd < 0) {
  //     fprintf(stderr, "ERROR: getting BPF program FD failed\n");
  //     return 1;
  //   }
  //   // Load BPF program
  //   fprintf(stderr, "Loading and verifying the code in the kernel\n");
  //   if (bpf_object__load(obj)) {
  //     fprintf(stderr, "ERROR: loading BPF object file failed\n");
  //     return 1;
  //   }

  //   // Attach

  //   // for (size_t i = 0; i < sizeof(tracepoints) / sizeof(tracepoints[0]);
  //   ++i)
  //   // {

  //   links[i] = bpf_program__attach_tracepoint(prog, "block", tracepoints[i]);
  //   if (libbpf_get_error(links[i])) {
  //     fprintf(stderr, "ERROR: Attaching BPF program to tracepoint %s
  //     failed\n",
  //             tracepoints[i]);
  //     return 1;
  //   }
  // }

  signal(SIGINT, sig_handler);

  printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

  struct bpf_map *map;
  map = bpf_object__find_map_by_name(obj, "hists");
  if (libbpf_get_error(map)) {
    fprintf(stderr, "ERROR: finding BPF map failed\n");
    return 1;
  }

  /* main: poll */
  while (1) {
    sleep(interval);
    // TODO: fix map and pass to the function below

    err = print_log2_hists(map);
    if (err)
      break;

    if (exiting)
      break;
  }

  bpf_object__close(obj);

  return 0;
}