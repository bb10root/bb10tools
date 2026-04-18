#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/neutrino.h>
#include <sys/mman.h>

#define L1_ENTRIES 4096
#define L2_ENTRIES 256

typedef struct {
    uint32_t ttbr0;
    uint32_t sctlr;
    uint32_t dacr;
    uint32_t ttbcr;
    uint32_t contextidr; // Для ASID
    uint32_t l2ctlr;     // L2 Cache Control (Krait specific)
} mmu_context_t;

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
        default: type = "Implementation Def"; break;
    }
    snprintf(desc, sizeof(desc), "%-15s | %s", type, (s ? "SH" : "nS"));
    return desc;
}

void kcall_safe_dump(void *arg) {
    mmu_context_t *ctx = (mmu_context_t *)arg;

    // Тільки стандартні регістри, які точно є в MSM8960
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ctx->ttbr0));    // База L1
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(ctx->sctlr));    // Control
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(ctx->dacr));     // Domains
    asm volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(ctx->contextidr)); // ASID

    // L2CTLR поки що НЕ чіпаємо, він може бути причиною крашу
    ctx->l2ctlr = 0xDEADBEEF;
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

int main() {
    if (ThreadCtl(_NTO_TCTL_IO, 0) == -1) return 1;

    mmu_context_t ctx;
    __Ring0(kcall_safe_dump, &ctx);

    uint32_t asid = ctx.contextidr & 0xFF;
    uint32_t afe = (ctx.sctlr >> 29) & 0x1;

    printf("=== MSM89xx Advanced System Snapshot ===\n");
    printf("CONTEXT ID: 0x%08X (ASID: %d)\n", ctx.contextidr, asid);
    printf("SCTLR:      0x%08X | DACR: 0x%08X\n", ctx.sctlr, ctx.dacr);
    printf("L2CTLR:     0x%08X (L2 Cache Config)\n", ctx.l2ctlr);
    printf("--------------------------------------------------------------------------------\n");

    uint32_t l1_phys = ctx.ttbr0 & 0xFFFFC000;
    uint32_t *l1_table = mmap_device_memory(NULL, 16384, PROT_READ, 0, l1_phys);

    for (int i = 0; i < L1_ENTRIES; i++) {
        uint32_t e = l1_table[i];
        if ((e & 0x3) == 0) continue;

        uint32_t vaddr = i << 20;
        if ((e & 0x3) == 1) { // Page Table
            uint32_t dom = (e >> 5) & 0xF;
            printf("[L1 Tab] V:0x%08X | Dom:%d (Stat:%d) | PXN:%d\n",
                   vaddr, dom, (ctx.dacr >> (dom * 2)) & 0x3, (e >> 2) & 1);
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
    return 0;
}
