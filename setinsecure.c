#include <libram.h>
int main(int argc, char const *argv[])
{
    uint32_t insecure;
    uint32_t addr, size;
    if (!get_asinfo_region("bootrommetrics", &addr, &size))
    {
        printf("0x%x 0x%x\n", addr, size);
        void *map = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_NOCACHE, MAP_PHYS | MAP_SHARED, NOFD, addr);

        if (map == MAP_FAILED)
        {
            return -1;
        }
        memcpy(&insecure, map + 0x7c, 4);
        printf("Device is %s (0x%x)\n", insecure ? "insecure" : "secure", insecure);
        if (insecure == 0)
        {
            insecure = -1;
            memcpy(map + 0x7c, &insecure, 4);
        }
        munmap(map, size);
    }

    return 0;
}
