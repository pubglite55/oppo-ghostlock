// init.c — minimal static init for the QEMU arm64 lab (Debian 5.10.218 guest).
//
// Built with the NDK as a STATIC aarch64 binary: no busybox, no libc, no shebang.
// The kernel execs this directly as /init.
//
//  * mounts proc/sys/dev/debugfs
//  * prints the facts we care about (version, KASLR, perf, kptr_restrict)
//  * dumps the kallsyms entries the guest target.h is generated from
//  * opens perf up (perf_event_paranoid=-1) and launches /data/exploit_static
//    with the C-stage environment
//  * drops into a REPL so the host can drive further stages

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/reboot.h>

static const char *WANT[] = {"_text", "_stext", "init_task", "init_cred",
                             "commit_creds", "prepare_creds", "core_sys_select",
                             "rb_erase", NULL};

static void cat1(const char *path, const char *label) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("%s: <not present>\n", label);
    return;
  }
  char buf[512];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n < 0) n = 0;
  buf[n] = 0;
  for (ssize_t i = 0; i < n; i++)
    if (buf[i] == '\n') buf[i] = ' ';
  printf("%s: %s\n", label, buf);
}

static void show(const char *p) {
  int fd = open(p, O_RDONLY);
  printf("%-34s : %s\n", p, fd >= 0 ? "present" : "absent");
  if (fd >= 0) close(fd);
}

static void dump_syms(void) {
  FILE *ks = fopen("/proc/kallsyms", "r");
  printf("--- kallsyms ---\n");
  if (!ks) {
    printf("cannot read /proc/kallsyms\n");
    return;
  }
  char line[256];
  while (fgets(line, sizeof(line), ks)) {
    char addr[32], type, name[160];
    if (sscanf(line, "%31s %c %159s", addr, &type, name) != 3) continue;
    for (int i = 0; WANT[i]; i++)
      if (!strcmp(name, WANT[i])) printf("%-18s %s\n", name, addr);
  }
  fclose(ks);
  printf("--- (end kallsyms) ---\n");
}

static int run_child(const char *path, char *const argv[], char *const envp[]) {
  pid_t p = fork();
  if (p == 0) {
    if (envp) execve(path, argv, envp);
    else execl(path, path, (char *)NULL);
    printf("(exec failed)\n");
    _exit(127);
  }
  int st = 0;
  waitpid(p, &st, 0);
  return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void repl(void) {
  char line[256];
  for (;;) {
    printf("lab# ");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) {
      sleep(1);
      continue;
    }
    size_t l = strlen(line);
    while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
    if (!l) continue;
    if (!strcmp(line, "exit") || !strcmp(line, "reboot")) {
      sync();
      reboot(RB_AUTOBOOT);
    }
    if (!strcmp(line, "poweroff")) {
      sync();
      reboot(RB_POWER_OFF);
    }
    /* no shell in this rootfs: interpret a couple of builtins */
    if (!strncmp(line, "cat ", 4)) {
      cat1(line + 4, line + 4);
      continue;
    }
    if (!strcmp(line, "kallsyms")) {
      dump_syms();
      continue;
    }
    if (!strcmp(line, "run")) {
      char *argv[] = {"exploit_static", NULL};
      printf("[rc=%d]\n", run_child("/data/exploit_static", argv, NULL));
      continue;
    }
    printf("(builtins: cat <path> | kallsyms | run | reboot | poweroff)\n");
  }
}

int main(void) {
  mkdir("/proc", 0755);
  mkdir("/sys", 0755);
  mkdir("/dev", 0755);
  mkdir("/tmp", 0755);
  mount("proc", "/proc", "proc", 0, NULL);
  mount("sysfs", "/sys", "sysfs", 0, NULL);
  mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
  mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);

  printf("\n================ QEMU LAB UP ================\n");
  cat1("/proc/version", "kernel");
  cat1("/proc/cmdline", "cmdline");
  cat1("/proc/sys/kernel/randomize_va_space", "randomize_va_space");
  cat1("/proc/sys/kernel/perf_event_paranoid", "perf_event_paranoid");
  cat1("/proc/sys/kernel/kptr_restrict", "kptr_restrict");
  show("/sys/fs/selinux");
  show("/dev/kmsg");
  cat1("/proc/sys/kernel/osrelease", "osrelease");
  printf("---------------------------------------------\n");
  dump_syms();

  /* guest is root: open up perf so the exploit's perf task-leak can run */
  {
    int fd = open("/proc/sys/kernel/perf_event_paranoid", O_WRONLY);
    if (fd >= 0) {
      write(fd, "-1", 2);
      close(fd);
    }
    cat1("/proc/sys/kernel/perf_event_paranoid", "perf_event_paranoid(after)");
  }

  if (access("/data/exploit_static", X_OK) == 0) {
    printf(">>> launching /data/exploit_static with the C-stage env\n");
    fflush(stdout);
    char *envp[] = {
        "PSELECT_SKIP_WARMUP=1", "PSELECT_SLIDE_TRIGGER=1", "PSELECT_RETRY=1",
        "PSELECT_CRED=1", "PSELECT_PERF_CRED=1", "PSELECT_PTR_MODE=1",
        "PSELECT_PTR_STAGE=C", "PSELECT_PTR_STRICT=1",
        "PSELECT_CHILD_POLLS=150", NULL};
    char *argv[] = {"exploit_static", NULL};
    printf(">>> exploit rc=%d\n", run_child("/data/exploit_static", argv, envp));
  } else {
    printf("(no /data/exploit_static)\n");
  }

  printf("================ READY (commands on stdin) ====\n");
  fflush(stdout);
  repl();
  return 0;
}