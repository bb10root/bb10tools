#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define CHUNK_SIZE  (1024 * 1024)   /* 1 MB */
#define PAGE_SIZE   4096

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = read(fd, p + done, len - done);
        if (r < 0) return -1;
        if (r == 0) return -2;   /* EOF раніше очікуваного */
            done += (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int memfd, infd;
    uint32_t start_phys, end_phys;
    uint32_t pos;
    const char *inname;
    uint32_t fail_count = 0;

    if (argc < 4) {
        printf("Usage: %s <start_phys_hex> <end_phys_hex> <infile>\n", argv[0]);
        printf("Example: %s 0x80000000 0x80FFFFFF dump.bin\n", argv[0]);
        printf("Range is [start, end] (end included)\n");
        return 1;
    }

    start_phys = (uint32_t)strtoul(argv[1], NULL, 0);
    end_phys   = (uint32_t)strtoul(argv[2], NULL, 0);
    inname     = argv[3];

    if (end_phys < start_phys) {
        fprintf(stderr, "Error: end must be >= start\n");
        return 1;
    }

    uint32_t total_len = (end_phys - start_phys) + 1;

    /* Перевірка розміру вхідного файлу */
    infd = open(inname, O_RDONLY);
    if (infd < 0) {
        perror("open infile");
        return 1;
    }
    off_t file_size = lseek(infd, 0, SEEK_END);
    if (file_size < 0) {
        perror("lseek");
        close(infd);
        return 1;
    }
    if ((uint32_t)file_size < total_len) {
        fprintf(stderr,
                "Error: file size (0x%lX) < requested range (0x%X)\n",
                (unsigned long)file_size, total_len);
        close(infd);
        return 1;
    }
    lseek(infd, 0, SEEK_SET);

    /* /dev/mem відкриваємо на запис */
    memfd = open("/dev/mem", O_RDWR | O_SYNC);
    if (memfd < 0) {
        perror("open /dev/mem");
        close(infd);
        return 1;
    }

    uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK_SIZE);
    if (!chunk_buf) {
        fprintf(stderr, "malloc failed\n");
        close(memfd);
        close(infd);
        return 1;
    }

    pos = 0;
    while (pos < total_len) {
        uint32_t cur_phys = start_phys + pos;
        uint32_t left     = total_len - pos;
        uint32_t cur_len  = (left > CHUNK_SIZE) ? CHUNK_SIZE : left;

        /* Вирівнювання на сторінку */
        uint32_t page_base = cur_phys & ~(uint32_t)(PAGE_SIZE - 1);
        uint32_t page_off  = cur_phys &  (uint32_t)(PAGE_SIZE - 1);
        uint32_t map_len   = page_off + cur_len;

        /* Читаємо дані з файлу */
        int rc = read_all(infd, chunk_buf, cur_len);
        if (rc == -2) {
            fprintf(stderr, "Unexpected EOF at file offset 0x%X\n", pos);
            break;
        } else if (rc != 0) {
            perror("read infile");
            break;
        }

        /* Маппінг з PROT_WRITE */
        void *map = mmap(NULL, map_len,
                         PROT_READ | PROT_WRITE, MAP_SHARED,
                         memfd, (off_t)page_base);

        if (map == MAP_FAILED) {
            fail_count++;
            fprintf(stderr,
                    "[FAIL] mmap phys=0x%08X len=0x%X -> skipped (errno=%d: %s)\n",
                    cur_phys, cur_len, errno, strerror(errno));
        } else {
            /* Копіюємо дані в пам'ять */
            memcpy((uint8_t *)map + page_off, chunk_buf, cur_len);

            /* Примусово скидаємо в фізичну пам'ять */
            if (msync(map, map_len, MS_SYNC) != 0) {
                perror("msync");
            }

            munmap(map, map_len);
        }

        pos += cur_len;

        /* Прогрес кожні 16 MB */
        if ((pos & 0x00FFFFFF) == 0 || pos == total_len) {
            printf("written 0x%08X / 0x%08X bytes (fails=%u)\n",
                   pos, total_len, fail_count);
            fflush(stdout);
        }
    }

    free(chunk_buf);
    close(infd);
    close(memfd);

    printf("DONE: wrote [0x%08X, 0x%08X] (%u bytes) from %s (fails=%u)\n",
           start_phys, end_phys, total_len, inname, fail_count);
    return 0;
}
