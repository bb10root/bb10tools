#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define CHUNK_SIZE   (1024 * 1024)   /* 1 MB */
#define PAGE_SIZE    4096

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;

    while (done < len) {
        ssize_t w = write(fd, p + done, len - done);
        if (w < 0) return -1;
        if (w == 0) return -1;
        done += (size_t)w;
    }
    return 0;
}

static int write_zeros(int fd, size_t len)
{
    static uint8_t zeros[4096];
    size_t left = len;

    while (left > 0) {
        size_t chunk = (left > sizeof(zeros)) ? sizeof(zeros) : left;
        if (write_all(fd, zeros, chunk) != 0) return -1;
        left -= chunk;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int memfd, outfd;
    uint32_t start_phys, end_phys;
    uint32_t pos;
    const char *outname;
    uint32_t fail_count = 0;

    if (argc < 4) {
        printf("Usage: %s <start_phys_hex> <end_phys_hex> <outfile>\n", argv[0]);
        printf("Example: %s 0x80000000 0x80FFFFFF dump.bin\n", argv[0]);
        printf("Range is [start, end] (end included)\n");
        return 1;
    }

    start_phys = (uint32_t)strtoul(argv[1], NULL, 0);
    end_phys   = (uint32_t)strtoul(argv[2], NULL, 0);
    outname = argv[3];

    if (end_phys < start_phys) {
        fprintf(stderr, "Error: end must be >= start\n");
        return 1;
    }

    /* inclusive end => +1 */
    uint32_t total_len = (end_phys - start_phys) + 1;

    memfd = open("/dev/mem", O_RDONLY | O_SYNC);
    if (memfd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    outfd = open(outname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outfd < 0) {
        perror("open outfile");
        close(memfd);
        return 1;
    }

    pos = 0;
    while (pos < total_len) {
        uint32_t cur_phys = start_phys + pos;
        uint32_t left = total_len - pos;
        uint32_t cur_len = (left > CHUNK_SIZE) ? CHUNK_SIZE : left;

        uint32_t page_base = cur_phys & ~(PAGE_SIZE - 1);
        uint32_t page_off  = cur_phys &  (PAGE_SIZE - 1);
        uint32_t map_len   = page_off + cur_len;

        void *map = mmap(NULL, map_len, PROT_READ, MAP_SHARED, memfd, page_base);
        if (map == MAP_FAILED) {
            fail_count++;

            fprintf(stderr,
                    "[FAIL] mmap phys=0x%08X len=0x%X -> zeros (errno=%d: %s)\n",
                    cur_phys, cur_len, errno, strerror(errno));

            if (write_zeros(outfd, cur_len) != 0) {
                perror("write zeros");
                close(outfd);
                close(memfd);
                return 1;
            }
        } else {
            if (write_all(outfd, (uint8_t *)map + page_off, cur_len) != 0) {
                perror("write");
                munmap(map, map_len);
                close(outfd);
                close(memfd);
                return 1;
            }
            munmap(map, map_len);
        }

        pos += cur_len;

        /* прогрес кожні 16MB */
        if ((pos & 0x00FFFFFF) == 0) {
            printf("dumped 0x%08X / 0x%08X bytes (fails=%u)\n",
                   pos, total_len, fail_count);
            fflush(stdout);
        }
    }

    close(outfd);
    close(memfd);

    printf("DONE: saved [0x%08X, 0x%08X] (%u bytes) to %s (fails=%u)\n",
           start_phys, end_phys, total_len, outname, fail_count);

    return 0;
}
