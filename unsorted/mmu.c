#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/neutrino.h>

typedef struct {
    uint32_t ttbr0;
} full_map_t;

// Допоміжна функція для розшифровки типу пам'яті за атрибутами TEX/C/B
const char* get_mem_type(uint32_t tex, uint32_t c, uint32_t b) {
    uint32_t res = (tex << 2) | (c << 1) | b;
    if (res == 0) return "Strongly-ordered";
    if (res == 1) return "Shareable Device";
    if (res == 4) return "Outer/Inner WT";
    if (res == 5) return "Outer/Inner WB";
    return "Normal/Other";
}

void kcall_full_mmu_scan(void *arg) {
    full_map_t *map = (full_map_t *)arg;
    uint32_t temp_ttbr0;

    // Отримуємо базу таблиці L1
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(temp_ttbr0));
    map->ttbr0 = temp_ttbr0;
    uint32_t *l1_table = (uint32_t *)(map->ttbr0 & 0xFFFFC000);

    printf("\n=== FULL SYSTEM MMU MAP (QNX Kernel Space) ===\n");
    printf("%-20s | %-10s | %-10s | %-12s | %s\n", "Virtual Range", "Phys Base", "Type", "Access", "Attributes");
    printf("---------------------|------------|------------|--------------|----------------\n");

    uint32_t start_vaddr = 0;
    int in_region = 0;
    uint32_t last_paddr = 0;
    uint32_t last_flags = 0;

    for (int i = 0; i < 4096; i++) {
        uint32_t entry = l1_table[i];
        uint32_t vaddr = i << 20;
        uint32_t paddr = 0;
        uint32_t flags = entry & 0xFFF; // Атрибути дескриптора
        int mapped = 0;

        if ((entry & 0x3) == 0x2) { // Section 1MB
            paddr = entry & 0xFFF00000;
            mapped = 1;
        } else if ((entry & 0x3) == 0x1) { // L2 Table present
            paddr = entry & 0xFFFFFC00; // Це адреса самої L2 таблиці
            mapped = 2;
        }

        // Логіка групування однакових регіонів для чистоти виводу
        if (mapped != in_region || (mapped == 1 && (paddr != last_paddr + 0x100000 || flags != last_flags))) {
            if (i > 0 && in_region != 0) {
                printf("0x%08X-0x%08X | ", start_vaddr, vaddr - 1);
                if (in_region == 1) {
                    uint32_t ap = (last_flags >> 10) & 0x3;
                    printf("0x%08X | Section    | AP:%-8d | TEX:%d C:%d B:%d\n",
                           last_paddr, ap, (last_flags >> 12) & 0x7, (last_flags >> 3) & 1, (last_flags >> 2) & 1);
                } else {
                    printf("0x%08X | L2 Table   | Dynamic      | Sub-page mapping\n", last_paddr);
                }
            }
            start_vaddr = vaddr;
            in_region = mapped;
            last_paddr = paddr;
            last_flags = flags;
        }

        if (mapped == 1) last_paddr = paddr;
    }
}

int main() {
    if (ThreadCtl(_NTO_TCTL_IO, 0) == -1) {
        perror("ThreadCtl");
        return 1;
    }

    full_map_t map;
    __Ring0(kcall_full_mmu_scan, &map);

    return 0;
}
