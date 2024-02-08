#include "iolatency.h"

static volatile bool exiting;


static void sig_handler(int sig) { exiting = true; }


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
    err = print_log2_hists(map);
    if (err)
      break;

    if (exiting)
      break;
  }

  bpf_object__close(obj);

  return 0;
}