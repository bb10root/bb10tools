/*
 * launcher.c
 *
 *  Created on:  Mar 18, 2025
 *  Modified on: Mar 15, 2026
 *      Author: lc
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/procmsg.h>
#include <sys/syspage.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <process.h>
#include <unistd.h>
#include <stdbool.h>

#include <libhash.h>
#include <libelf.h>
#include "signatures.h"
#include <signature.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/procfs.h>
#include <devctl.h>
#include <limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

int find_pid_by_name(const char *name)
{
  DIR *d = opendir("/proc");
  if (!d) return -1;

  struct dirent *ent;
  int found_pid = -1;

  while ((ent = readdir(d))) {
    int pid = atoi(ent->d_name);
    if (pid <= 0) continue;

    char path[PATH_MAX];
    char exe_content[PATH_MAX];

    // Формуємо шлях до exefile
    snprintf(path, sizeof(path), "/proc/%d/exefile", pid);

    int fd = open(path, O_RDONLY);
    if (fd != -1) {
      ssize_t n = read(fd, exe_content, sizeof(exe_content) - 1);
      close(fd);

      if (n > 0) {
        exe_content[n] = '\0';

        // Видаляємо можливий символ переведення рядка в кінці
        char *newline = strchr(exe_content, '\n');
        if (newline) *newline = '\0';

        // Отримуємо чисте ім'я файлу (після останнього '/')
        char *filename = strrchr(exe_content, '/');
        if (filename) {
          filename++; // переходимо до символу після '/'
        } else {
          filename = exe_content;
        }

        // ПОРІВНЯННЯ
        // Використовуйте strcmp для точного збігу ("launcher")
        // або strstr, якщо хочете знаходити "webkit-launcher" за словом "launcher"
        if (strcmp(filename, name) == 0) {
          found_pid = pid;
          break;
        }
      }
    }
  }

  closedir(d);
  return found_pid;
}

#define MAX_SEGMENTS 1024
#define MAX_THREADS 512

#define ELF_FLAGS (PROT_EXEC)

void dump_procfs_map_info(int fd, int pid)
{
  // fetch information about the memory regions for this pid
  procfs_mapinfo *membufs;
  procfs_status my_status, old_status;

  int threads_count = 0;
  procfs_greg my_greg;

  int size, j;

  int nmembuf;
  int sts;
  int res;
  int target = 0;
  int new_sp, new_ip;
  unsigned char *xbuff;

  printf("DCMD_PROC_MAPINFO\n");
  sts = devctl(fd, DCMD_PROC_MAPINFO, NULL, 0, &nmembuf);
  if (sts != EOK)
  {
    fprintf(stderr, "DCMD_PROC_MAPINFO process %d, error %d (%s)\n", pid, sts,
            strerror(sts));
    exit(EXIT_FAILURE);
  }
  printf("PAGEDATA ok (%d)\n", nmembuf);

  membufs = malloc(sizeof(procfs_mapinfo) * nmembuf);
  if (!membufs)
  {
    printf("membufs alloc error");
    exit(1);
  }

  printf("DCMD_PROC_MAPINFO\n");
  sts = devctl(fd, DCMD_PROC_MAPINFO, membufs,
               sizeof(procfs_mapinfo) * nmembuf, &nmembuf);
  if (sts != EOK)
  {
    fprintf(stderr, "DCMD_PROC_MAPINFO process %d, error %d (%s)\n", pid, sts,
            strerror(sts));
    exit(EXIT_FAILURE);
  }

  _Uint64t base_c = membufs[0].vaddr;
  _Uint64t base_launcher = 0;
  _Uint64t data_launcher = 0;
  _Uint64t data_size = 0;
  int kk = 0;

  for (int i = 1; i < nmembuf; i++)
  {
    if (membufs[i].flags & PROT_EXEC)
    {
      kk = i;
      break;
    }
  }
  if (!kk)
    exit(EXIT_FAILURE);

  base_launcher = membufs[kk].vaddr;
  data_launcher = membufs[kk + 1].vaddr;
  data_size = membufs[kk + 1].size;

  printf("libc addr: 0x%08llX\n", base_c);
  printf("launcher addr: 0x%08llX\n", base_launcher);
  printf("launcher data addr: 0x%08llX\n", data_launcher);

  printf("Pause process\n");
  memset(&old_status, 0, sizeof(old_status));

  devctl(fd, DCMD_PROC_STOP, &old_status, sizeof(old_status), NULL);

  const char *devb = "/base/sbin/launcher";
  int l_fd = open(devb, O_RDONLY);
  if (l_fd < 0)
  {
    perror("devb open");
    exit(1);
  }

  struct stat st;
  fstat(l_fd, &st);

  // Відображаємо файл
  void *elf_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, l_fd, 0);
  if (elf_map == MAP_FAILED)
  {
    perror("mmap");
    goto close_file;
  }

  elf_ctx_t ctx;
  if (elf_init_ctx(&ctx, elf_map) != 0)
  {
    perror("Not elf");
    goto unmap_elf;
  }
  code_section_t text = elf_get_text(&ctx);

  find_signatures(text.data, text.size);

  uint32_t code_base = base_c;
  uint32_t launcher_base = data_launcher;

  printf("Read memory\n");

  uint8_t b;
  uint32_t delta = 0;

  Signature *sig = find_signature_by_name("isDeviceSecure");
  if (!sig->found)
  {
#ifdef DEBUG
    printf("%s not found\n", sig->name);
#endif
    goto unmap_elf;
  }
  uint8_t *ptr = text.data + sig->found_offset + 0x20;
  delta = *(uint32_t *)ptr + sig->found_offset + 0x0C;

  off_t addr = (off_t)(launcher_base + delta);

  if (addr >= data_launcher && addr < data_launcher + data_size)
  {

    res = pread(fd, &b, 1, addr);
    if (res != 1)
    {
      printf("pread res=%d errno=%d (%s)\n", res, errno, strerror(errno));
      goto unmap_elf;
    }
    printf("target addr: 0x%08X\n", addr);
    printf("target byte: %d\n", b);

    b = 1;

    printf("Write memory\n");
    res = pwrite(fd, &b, 1, addr);
    if (res != 1)
    {
      perror("pwrite");
    }
    res = pread(fd, &b, 1, addr);
    if (res != 1)
    {
      printf("pread res=%d errno=%d (%s)\n", res, errno, strerror(errno));
      goto unmap_elf;
    }
    printf("changed byte: %d\n", b);
  }

unmap_elf:
  munmap(elf_map, st.st_size);
close_file:
  close(l_fd);

  procfs_run run;
  memset(&run, 0, sizeof(run));
  printf("Resume process\n");
  devctl(fd, DCMD_PROC_RUN, &run, sizeof(run), NULL);
  free(membufs);
  printf("Done!\n");
}

void iterate_process(int pid)
{
  char paths[PATH_MAX];
  int fd;

  sprintf(paths, "/proc/%d/as", pid);

  if ((fd = open64(paths, O_RDWR)) == -1)
  {
    printf("Can't open '%s' for RW!\n", paths);
    return;
  }
  dump_procfs_map_info(fd, pid);
  close(fd);
}

#define APP_NAME "BB10 launcher patcher(uni)"
#define APP_VERSION "1.0.1"

#include <stdio.h>
#include <banner.h>

int main(int argc, char **argv)
{
  display_system_banner();
  int g_pid;

  g_pid = find_pid_by_name("launcher");
  if (g_pid == -1)
    return EXIT_FAILURE;
  printf("PID: %d\n", g_pid);
  iterate_process(g_pid);

  return EXIT_SUCCESS;
}
