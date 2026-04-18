#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/neutrino.h>
#include <sys/mman.h>

#define L1_ENTRIES 4096
#define L2_ENTRIES 256

typedef struct {
    uint32_t ttbr0;
    uint32_t l1_copy[L1_ENTRIES];
} l1_dump_t;

// Розшифровка прав доступу (Access Permissions)
const char* decode_ap(uint32_t ap) {
    switch (ap) {
        case 0: return "No Access";
        case 1: return "Priv:RW / User:None";
        case 2: return "Priv:RW / User:RO";
        case 3: return "Full:RW";
        default: return "Unknown";
    }
}

// Крок 1: Тільки копіювання L1 у Ring 0
void kcall_get_l1(void *arg) {
    l1_dump_t *dump = (l1_dump_t *)arg;
    uint32_t temp_ttbr;

    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(temp_ttbr));
    dump->ttbr0 = temp_ttbr;

    // Фізична адреса L1 (вирівняна по 16КБ)
    uint32_t *l1_phys_ptr = (uint32_t *)(dump->ttbr0 & 0xFFFFC000);

    // Пряме копіювання (в QNX ядро бачить таблиці)
    for (int i = 0; i < L1_ENTRIES; i++) {
        dump->l1_copy[i] = l1_phys_ptr[i];
    }
}

// Крок 2: Аналіз сторінок L2 (User Mode)
void analyze_l2_user(uint32_t l2_paddr, uint32_t vaddr_base) {
    uint32_t *l2_virt = mmap_device_memory(NULL, 1024, PROT_READ, 0, l2_paddr);

    if (l2_virt == MAP_FAILED) {
        printf("      [!] Failed to map L2 at 0x%08X\n", l2_paddr);
        return;
    }

    for (int j = 0; j < L2_ENTRIES; j++) {
        uint32_t entry = l2_virt[j];
        uint32_t type = entry & 0x3;

        if (type == 0) continue; // Unmapped

        uint32_t page_vaddr = vaddr_base + (j << 12);
        uint32_t page_paddr;
        uint32_t ap, xn;

        if (type == 1) { // Large Page (64KB)
            page_paddr = entry & 0xFFFF0000;
            ap = (entry >> 10) & 0x3;
            xn = (entry >> 15) & 0x1;
        } else { // Small Page (4KB)
            page_paddr = entry & 0xFFFFF000;
            ap = (entry >> 4) & 0x3;
            xn = entry & 0x1; // NX bit для Small Page на 0-й позиції
        }

        printf("   [L2] V:0x%08X -> P:0x%08X | %s | %s | %s\n",
                page_vaddr, page_paddr,
                (type == 1 ? "64K" : " 4K"),
                decode_ap(ap),
                (xn ? "NX (No-Exec)" : "EXEC OK"));
    }

    munmap_device_memory(l2_virt, 1024);
}

int main() {
    // Потрібно для mmap_device_memory та __Ring0
    if (ThreadCtl(_NTO_TCTL_IO, 0) == -1) {
        perror("ThreadCtl");
        return 1;
    }

    l1_dump_t dump;
    printf("--- MMU Snapshot Start ---\n");

    if (__Ring0(kcall_get_l1, &dump) == -1) {
        perror("__Ring0 failed");
        return 1;
    }

    for (int i = 0; i < L1_ENTRIES; i++) {
        uint32_t entry = dump.l1_copy[i];
        uint32_t type = entry & 0x3;
        uint32_t vaddr = i << 20;

        if (type == 0) continue; // Unmapped

        if (type == 1) { // Page Table
            uint32_t l2_paddr = entry & 0xFFFFFC00;
            printf("[L1 Table] V:0x%08X -> L2 Phys:0x%08X\n", vaddr, l2_paddr);
            analyze_l2_user(l2_paddr, vaddr);
        }
        else if (type == 2) { // Section (1MB)
            uint32_t paddr = entry & 0xFFF00000;
            uint32_t ap = (entry >> 10) & 0x3;
            uint32_t xn = (entry >> 4) & 0x1;
            printf("[L1 Sect ] V:0x%08X -> P:0x%08X | 1MB | %s | %s\n",
                    vaddr, paddr, decode_ap(ap), (xn ? "NX" : "EXEC"));
        }
    }

    printf("--- MMU Snapshot End ---\n");
    return 0;
}
