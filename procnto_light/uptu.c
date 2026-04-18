#include <stdint.h>
#include <stdlib.h>
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
#include <sys/procfs.h>

const char *procnto = "/proc/1/as";

#define APP_NAME "BB10 PathTrust unlocker(uni)"
#define APP_VERSION "1.0.0"

#include <banner.h>

int main(int argc, char **argv)
{
    display_system_banner();

    int fd = open(procnto, O_RDWR);
    if (fd < 0)
    {
        perror("procnto open");
        return 1;
    }
    int maps;

    int ret = devctl(fd, DCMD_PROC_MAPINFO, NULL, 0, &maps);
    if (ret)
        goto close_file;

    int maps_size = sizeof(procfs_mapinfo) * maps;
    /* allocate space for page info */
    procfs_mapinfo *membufs = malloc(sizeof(maps_size) * maps);
    if (!maps)
        goto close_file;

    ret = devctl(fd, DCMD_PROC_MAPINFO, membufs, maps_size, &maps);
    if (ret)
        goto free_mem;
#ifdef DEBUG
    printf("text: 0x%llx 0x%llx \n", membufs[0].vaddr, membufs[0].size);
    printf("data: 0x%llx 0x%llx \n", membufs[1].vaddr, membufs[1].size);
#endif

    void *data = malloc(membufs[0].size);
    if (pread64(fd, data, membufs[0].size, membufs[0].vaddr) < 0)
        goto free_data;

    find_signatures(data, membufs[0].size);

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
        uint8_t *ptr = data + ldr_off;

        uint32_t ins = *(uint32_t *)ptr;
#ifdef DEBUG
        printf("0x%x ins: 0x%X\n", ldr_off, ins);
#endif

        uint32_t trust_ptr_off = calculate_arm_pc_relative_address(ldr_off, ins); //

        uint32_t *ptr_trust_locked =
            (uint32_t *)(data + trust_ptr_off);
        uint32_t delta = *ptr_trust_locked - membufs[0].vaddr; // trust_locked offset relative to start .text(code) section

        uint32_t trust_locked;
        if (pread64(fd, &trust_locked, sizeof(trust_locked), membufs[0].vaddr + delta) < 0)
            goto free_data;

#ifdef DEBUG
        printf("delta: 0x%x\n", delta);
        printf("trust_locked[0x%x] = %d\n", (uint32_t)(membufs[0].vaddr + delta), trust_locked);
#endif
        if (trust_locked == 1)
        {
            trust_locked = 0x0;
            if (pwrite64(fd, &trust_locked, sizeof(trust_locked), membufs[0].vaddr + delta) < 0)
                goto free_data;
        }
        else
            printf("Already unlocked\n");
    }
free_data:
    free(data);

free_mem:
    free(membufs);

close_file:
    close(fd);

    return EXIT_SUCCESS;
}
