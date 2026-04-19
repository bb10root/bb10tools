/*
 * launcher.c
 *
 * Created on:  Mar 18, 2025
 * Modified on: Apr 19, 2026
 * Author: lc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <devctl.h>
#include <sys/stat.h>

#include <libhash.h>
#include <libelf.h>
#include "signatures.h"
#include <signature.h>

#define APP_NAME "BB10 launcher patcher(uni)"
#define APP_VERSION "1.1.0"
#define MAX_SEGMENTS 1024

#include <banner.h>

const char *TARGET_PATH = "/base/sbin/launcher";

/**
 * Знаходить PID процесу за його повним шляхом або ім'ям файлу.
 */
int find_pid_by_name(const char *name, int strict)
{
  DIR *d = opendir("/proc");
  if (!d)
    return -1;

  struct dirent *ent;
  int found_pid = -1;

  while ((ent = readdir(d)))
  {
    int pid = atoi(ent->d_name);
    if (pid <= 0)
      continue;

    char path[PATH_MAX];
    char exe_content[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/exefile", pid);

    int fd = open(path, O_RDONLY);
    if (fd != -1)
    {
      ssize_t n = read(fd, exe_content, sizeof(exe_content) - 1);
      close(fd);

      if (n > 0)
      {
        exe_content[n] = '\0';
        char *newline = strchr(exe_content, '\n');
        if (newline)
          *newline = '\0';

        if (strict)
        {
          if (strstr(exe_content, name) != NULL)
          {
            found_pid = pid;
            break;
          }
        }
        else
        {
          char *filename = strrchr(exe_content, '/');
          filename = (filename) ? filename + 1 : exe_content;
          if (strcmp(filename, name) == 0)
          {
            found_pid = pid;
            break;
          }
        }
      }
    }
  }
  closedir(d);
  return found_pid;
}

/**
 * Виконує патч пам'яті за вказаним відносним зміщенням.
 */
void patch_process_memory(int proc_fd, uint32_t offset_from_base)
{
  procfs_mapinfo *membufs = NULL;
  procfs_status old_status;
  int nmembuf, sts;

  // 1. Отримуємо карту пам'яті процесу
  sts = devctl(proc_fd, DCMD_PROC_MAPINFO, NULL, 0, &nmembuf);
  if (sts != EOK)
  {
    fprintf(stderr, "Error getting mapinfo size: %s\n", strerror(sts));
    return;
  }

  membufs = malloc(sizeof(procfs_mapinfo) * nmembuf);
  if (!membufs)
    return;

  sts = devctl(proc_fd, DCMD_PROC_MAPINFO, membufs, sizeof(procfs_mapinfo) * nmembuf, &nmembuf);
  if (sts != EOK)
  {
    free(membufs);
    return;
  }

  // 2. Знаходимо базу лаунчера (перший виконуваний сегмент після libc)
  uint64_t base_launcher = 0;
  for (int i = 1; i < nmembuf; i++)
  {
    if (membufs[i].flags & PROT_EXEC)
    {
      base_launcher = membufs[i].vaddr;
      break;
    }
  }

  if (base_launcher == 0)
  {
    fprintf(stderr, "Could not find executable segment\n");
    free(membufs);
    return;
  }

  printf("Launcher base: 0x%08llX\n", base_launcher);
  uintptr_t target_vaddr = (uintptr_t)(base_launcher + offset_from_base);

  // 3. Зупиняємо процес
  devctl(proc_fd, DCMD_PROC_STOP, &old_status, sizeof(old_status), NULL);

  uint8_t val;
  if (pread(proc_fd, &val, 1, target_vaddr) == 1)
  {
    printf("Current byte at 0x%08X: %d\n", target_vaddr, val);
    val = 1; // Патч
    if (pwrite(proc_fd, &val, 1, target_vaddr) == 1)
    {
      printf("Patch applied successfully at 0x%08X!\n", target_vaddr);
    }
    else
    {
      perror("pwrite failed");
    }
  }
  else
  {
    perror("pread failed");
  }

  // 4. Запуск процесу назад
  procfs_run run;
  memset(&run, 0, sizeof(run));
  devctl(proc_fd, DCMD_PROC_RUN, &run, sizeof(run), NULL);
  free(membufs);
}

int main(int argc, char **argv)
{
  display_system_banner();

  uint32_t patch_offset = 0;
  bool sig_found = false;

  int l_fd = open(TARGET_PATH, O_RDONLY);
  if (l_fd < 0)
  {
    perror("Source file open failed");
    return EXIT_FAILURE;
  }

  struct stat st;
  fstat(l_fd, &st);
  void *elf_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, l_fd, 0);
  if (elf_map == MAP_FAILED)
  {
    close(l_fd);
    return EXIT_FAILURE;
  }

  elf_ctx_t ctx;
  if (elf_init_ctx(&ctx, elf_map) == 0)
  {
    code_section_t text = elf_get_text(&ctx);
    find_signatures(text.data, text.size);

    Signature *sig = find_signature_by_name("isDeviceSecure");
    if (sig && sig->found)
    {
      // Розрахунок відносного зміщення (offset)
      uint8_t *ptr = text.data + sig->found_offset + 0x20;
      uint32_t pool_value = *(uint32_t *)ptr;
      uint32_t insn_pc = (uint32_t)(sig->found_offset + 8);
      patch_offset = pool_value + insn_pc + 4;
      sig_found = true;
    }
  }

  munmap(elf_map, st.st_size);
  close(l_fd);

  if (!sig_found)
  {
    fprintf(stderr, "Signature 'isDeviceSecure' not found in binary.\n");
    return EXIT_FAILURE;
  }

  int pid = find_pid_by_name(TARGET_PATH, 1);
  if (pid == -1)
  {
    fprintf(stderr, "Target process %s not found.\n", TARGET_PATH);
    return EXIT_FAILURE;
  }

  printf("Target PID: %d, Relative Patch Offset: 0x%08X\n", pid, patch_offset);

  char proc_path[32];
  snprintf(proc_path, sizeof(proc_path), "/proc/%d/as", pid);

  int fd = open(proc_path, O_RDWR);
  if (fd == -1)
  {
    perror("Failed to open process address space");
    return EXIT_FAILURE;
  }

  patch_process_memory(fd, patch_offset);
  close(fd);

  return EXIT_SUCCESS;
}