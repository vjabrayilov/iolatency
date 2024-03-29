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
  __u32 key;
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

 static inline void print_stars(unsigned int val, unsigned int val_max, int width) {
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
static inline void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type) {
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

static inline int print_log2_hists(struct bpf_map *hists) {
  struct hist_key lookup_key = {.key = -1}, next_key;
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

  lookup_key.key = -1;
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
