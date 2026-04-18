#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/neutrino.h>
#include <sys/mman.h>

#define L1_ENTRIES 4096
#define L2_ENTRIES 256

typedef struct {
    uint32_t midr;
    uint32_t ttbr0;
    uint32_t ttbr1;
    uint32_t ttbcr;
    uint32_t sctlr;
    uint32_t dacr;
    uint32_t contextidr;
} mmu_context_t;

// Декодування прав доступу (класичний ARMv7 без AFE)
const char* decode_ap(uint32_t ap, uint32_t afe) {
    if (afe) {
        uint32_t access = (ap >> 1) & 0x3;
        switch (access) {
            case 0: return "Priv:RW / User:None";
            case 1: return "Full:RW";
            case 2: return "Priv:RO / User:None";
            case 3: return "Full:RO";
            default: return "Unknown";
        }
    } else {
        switch (ap) {
            case 0: return "No Access";
            case 1: return "Priv:RW / User:None";
            case 2: return "Priv:RW / User:RO";
            case 3: return "Full:RW";
            case 5: return "Priv:RO / User:None";
            case 6: return "Full:RO";
            default: return "Reserved";
        }
    }
}

const char* decode_mem_attr(uint32_t tex, uint32_t c, uint32_t b, uint32_t s) {
    uint32_t tcb = (tex << 2) | (c << 1) | b;
    static char desc[64];
    const char *type;
    switch (tcb) {
        case 0: type = "Strongly-ordered"; break;
        case 1: type = "Device (Shareable)"; break;
        case 2: type = "Write-Through"; break;
        case 3: type = "Write-Back (NoAlloc)"; break;
        case 4: type = "Non-cacheable"; break;
        case 7: type = "Write-Back (Alloc)"; break;
        default: type = "Impl Def"; break;
    }
    snprintf(desc, sizeof(desc), "%-15s | %s", type, (s ? "SH" : "nS"));
    return desc;
}

void analyze_l2(uint32_t l2_paddr, uint32_t vbase, uint32_t afe) {
    uint32_t *l2_virt = mmap_device_memory(NULL, 1024, PROT_READ, 0, l2_paddr);
    if (l2_virt == MAP_FAILED) return;

    for (int j = 0; j < L2_ENTRIES; j++) {
        uint32_t e = l2_virt[j];
        if ((e & 0x3) == 0) continue;

        uint32_t vaddr = vbase + (j << 12);
        uint32_t ap = ((e >> 4) & 0x3) | ((e >> 7) & 0x4);
        uint32_t s = (e >> 10) & 0x1;
        uint32_t nG = (e >> 11) & 0x1;
        uint32_t xn = e & 0x1;

        printf("  [L2] V:0x%08X -> P:0x%08X | %-20s | %s | %s | %s\n",
               vaddr, e & 0xFFFFF000, decode_ap(ap, afe),
               decode_mem_attr((e >> 6) & 0x7, (e >> 3) & 1, (e >> 2) & 1, s),
               (xn ? "NX" : "X "), (nG ? "nG" : "G "));
    }
    munmap_device_memory(l2_virt, 1024);
}

void dump_l1_table(uint32_t ttbr, uint32_t start_idx, uint32_t end_idx, uint32_t afe, uint32_t dacr, const char* label) {
    uint32_t l1_phys = ttbr & 0xFFFFC000;
    // Розмір mmap залежить від кількості записів, але для безпеки візьмемо повну таблицю 16КБ
    uint32_t *l1_table = mmap_device_memory(NULL, 16384, PROT_READ, 0, l1_phys);
    if (l1_table == MAP_FAILED) return;

    printf("\n--- Analyzing %s (Base P:0x%08X) ---\n", label, l1_phys);
    for (uint32_t i = start_idx; i < end_idx; i++) {
        uint32_t e = l1_table[i];
        if ((e & 0x3) == 0) continue;

        uint32_t vaddr = i << 20;
        if ((e & 0x3) == 1) { // Page Table
            uint32_t dom = (e >> 5) & 0xF;
            printf("[L1 Tab] V:0x%08X | Dom:%d (Stat:%d)\n",
                   vaddr, dom, (dacr >> (dom * 2)) & 0x3);
            analyze_l2(e & 0xFFFFFC00, vaddr, afe);
        } else { // Section
            uint32_t ap = ((e >> 10) & 0x3) | ((e >> 13) & 0x4);
            uint32_t xn = (e >> 4) & 0x1;
            uint32_t pxn = e & 0x1;
            printf("[L1 Sec] V:0x%08X -> P:0x%08X | %-20s | %s | X:%s%s\n",
                   vaddr, e & 0xFFF00000, decode_ap(ap, afe),
                   decode_mem_attr((e >> 12) & 0x7, (e >> 3) & 1, (e >> 2) & 1, (e >> 16) & 1),
                   (xn ? "NX" : "X "), (pxn ? " PXN" : ""));
        }
    }
    munmap_device_memory(l1_table, 16384);
}

void kcall_registers(void *arg) {
    mmu_context_t *ctx = (mmu_context_t *)arg;
    asm volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(ctx->midr));
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ctx->ttbr0));
    asm volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ctx->ttbr1));
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ctx->ttbcr));
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(ctx->sctlr));
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(ctx->dacr));
    asm volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(ctx->contextidr));
}

int main() {
    if (ThreadCtl(_NTO_TCTL_IO, 0) == -1) return 1;

    mmu_context_t ctx;
    __Ring0(kcall_registers, &ctx);

    uint32_t n = ctx.ttbcr & 0x7;
    uint32_t afe = (ctx.sctlr >> 29) & 0x1;

    // Розрахунок межі розподілу між TTBR0 та TTBR1
    // Межа = 0xFFFFFFFF >> n. Наприклад, якщо n=1, межа 0x7FFFFFFF
    uint32_t boundary_idx = (n == 0) ? L1_ENTRIES : (L1_ENTRIES >> n);

    printf("=== MSM8974 Dual-TTBR Snapshot ===\n");
    printf("TTBCR: 0x%08X (N=%d) | Boundary Index: %d\n", ctx.ttbcr, n, boundary_idx);
    printf("TTBR0: 0x%08X | TTBR1: 0x%08X\n", ctx.ttbr0, ctx.ttbr1);
    printf("SCTLR: 0x%08X | DACR:  0x%08X\n", ctx.sctlr, ctx.dacr);

    // Аналізуємо TTBR0 (User Space / Lower Kernel)
    dump_l1_table(ctx.ttbr0, 0, boundary_idx, afe, ctx.dacr, "TTBR0");

    // Аналізуємо TTBR1 (Upper Kernel Space), якщо N > 0
    if (n > 0) {
        dump_l1_table(ctx.ttbr1, boundary_idx, L1_ENTRIES, afe, ctx.dacr, "TTBR1");
    }

    return 0;
}
