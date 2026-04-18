#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
/* For "open()" */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/neutrino.h>
#include <errno.h>
#include "nto_sig.h"
#include <signature.h>
#include <libarm.h>
#include <libelf.h>
#include <libram.h>

#pragma pack(push, 1)
typedef struct
{
    uint16_t cmd;    /* 0x73 */
    uint16_t flags;  /* r0 */
    uint32_t pid;    /* r1 */
    uint32_t dev;    /* r2 */
    uint32_t zero0;  /* 0 */
    uint64_t ino;    /* (r8:r9) */
    uint8_t pad[16]; /*  */
} trustpath_msg_t;
#pragma pack(pop)

static int trustpath_msg(uint16_t flags, uint32_t pid, uint32_t dev, uint64_t ino)
{
    trustpath_msg_t msg;
    uint32_t reply = 0;

    memset(&msg, 0, sizeof(msg));

    msg.cmd = 0x73;
    msg.flags = flags;
    msg.pid = pid;
    msg.dev = dev;
    msg.zero0 = 0;
    msg.ino = ino;

    if (MsgSendnc(0x40000000, &msg, sizeof(msg), &reply, 0) == -1)
        return -1;

    return 0;
}

int trust(const char *path, uint16_t flags)
{
    int exit_code;
    int fd = open64(path, 0);
    if (fd < 0)
    {
        fprintf(stderr, "open for '%s' failed: %d\n", path, errno);
        return 2;
    }

    struct stat64 st;
    if (fstat64(fd, &st) < 0)
    {
        fprintf(stderr, "fstat for '%s' failed: %d\n", path, errno);
        close(fd);
        return 2;
    }

    struct _server_info si;
    memset(&si, 0, sizeof(si));

    if (ConnectServerInfo(0, fd, &si) < 0)
    {
        fprintf(stderr, "ConnectServerInfo for '%s' failed: %d\n", path, errno);
        close(fd);
        return 2;
    }

    uint32_t pid = (uint32_t)si.pid;
    uint32_t dev = (uint32_t)st.st_dev;
    uint64_t ino = (uint64_t)st.st_ino;

    int rc = trustpath_msg(flags, pid, dev, ino);

    if (rc >= 0)
        errno = 0;

    if (errno == 0)
    {
        printf("'%s': trusted\n", path);
    }
    else if (errno == 1)
    {
        if (exit_code == 0)
            exit_code = 1;

        printf("'%s': untrusted\n", path);
    }
    else
    {
        printf("'%s': failure(%d)\n", path, errno);
        exit_code = 2;
    }

    close(fd);
    return exit_code;
}

int add_list = 0;
int clear_list = 0;
int patch_r0 = 0;
int clear_lock = 0;

const char *procnto = "/proc/boot/procnto-smp-instr";

#define APP_NAME "BB10 procnto patcher(uni)"
#define APP_VERSION "1.0.0"

#include <banner.h>

int main(int argc, char **argv)
{
    display_system_banner();

    char c;
    while ((c = getopt(argc, argv, "cura")) != -1)
    {
        switch (c)
        {
        case 'a':
            add_list = 1;
            break;
        case 'c':
            add_list = 1;
            clear_list = 1;
            break;
        case 'u':
            clear_lock = 1;
            break;
        case 'r':
            patch_r0 = 1;
            break;
        }
    }

    if (clear_lock || patch_r0)
    {

        int fd = open(procnto, O_RDONLY);
        if (fd < 0)
        {
            perror("procnto open");
            exit(1);
        }

        struct stat st;
        fstat(fd, &st);

        void *elf_map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (elf_map == MAP_FAILED)
        {
            perror("mmap");
            goto close_file;
        }

        uint32_t elf_hash = xxHash32_Universal(elf_map, 256, 0);
        munmap(elf_map, st.st_size);

        uint32_t addr = 0;
        uint32_t size = 0;

        if (get_asinfo_region("bootram", &addr, &size) != 0)
        {
#ifdef DEBUG
            printf("Region 'bootram' not found.\n");
#endif
            exit(1);
        }
#ifdef DEBUG
        printf("Found region 'bootram':\n");
        printf("  Address: 0x%08x\n", addr);
        printf("  Size:    %u bytes\n", size);
#endif
        void *ram_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PHYS | MAP_SHARED, NOFD, addr);

        if (ram_map == MAP_FAILED)
        {
#ifdef DEBUG
            printf("mmap failed!");
#endif
            goto close_file;
        }

        void *target_ram = find_elf_in_memory(ram_map, (ram_map + size - 1), elf_hash);

        if (target_ram == NULL)
        {
#ifdef DEBUG
            printf("find_elf failed!");
#endif
            goto unmap_mem;
        }
#ifdef DEBUG
        printf("Target RAM region: 0x%x\n", addr + (uint32_t)(target_ram - ram_map));
#endif
        elf_ctx_t ctx;
        elf_init_ctx(&ctx, target_ram);
        code_section_t text = elf_get_text(&ctx);
        find_signatures(text.data, text.size);

        if (patch_r0)
        {
            Signature *sig = find_signature_by_name("ker_ring0");
            if (!sig->found)
            {
#ifdef DEBUG
                printf("%s not found. Already patched?\n", sig->name);
#endif
            }
            else
            {
                uint8_t *ptr = text.data + sig->found_offset + 0x10;
                *(uint32_t *)ptr = 0xE320F000;
            }
        }
        if (clear_lock)
        {
            Signature *sig = find_signature_by_name("pathmgr_trust_handler");
            if (!sig->found)
            {
#ifdef DEBUG
                printf("%s not found.\n", sig->name);
#endif
            }
            else
            {
                uint32_t ldr_off = sig->found_offset + 0x34;
                uint8_t *ptr = text.data + ldr_off;

                uint32_t ins = *(uint32_t *)ptr;
#ifdef DEBUG
                printf("0x%x ins: 0x%X\n", ldr_off, ins);
#endif

                uint32_t trust_ptr_off = calculate_arm_pc_relative_address(ldr_off, ins); //

                uint32_t *ptr_trust_locked =
                    (uint32_t *)(text.data + trust_ptr_off);
                uint32_t delta = *ptr_trust_locked - text.vaddr; // trust_locked offset relative to start .text(code) section

                uint32_t *trust_locked = (uint32_t *)(text.data + delta);

#ifdef DEBUG
                printf("delta: 0x%x\n", delta);
                printf("trust_locked[0x%x] = %d\n", *ptr_trust_locked, *trust_locked);
#endif
                if ((*(uint32_t *)trust_locked) == 1)
                    *(uint32_t *)trust_locked = 0x0;
                else
#ifdef DEBUG
                    printf("Already unlocked\n", delta);
#endif
                if (clear_list)
                {
                    printf("Creating own pathtrust list\n");
                    uint32_t *trust_head = (uint32_t *)(text.data + delta + 4);
                    *trust_head = 0;
                }
                if (add_list)
                {
                    printf("Add to pathtrust list\n");
                    trust("/proc/boot", 0);
                    trust("/base", 0);
                    trust("/radio", 0);
                    trust("/", 0);
                    trust("/tmp", 0);
                }
            }
        }

        msync(ram_map, size, MS_SYNC);
    unmap_mem:
        munmap(ram_map, size);
    close_file:
        close(fd);
    }

    return EXIT_SUCCESS;
}
