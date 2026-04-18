#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/neutrino.h>
#include <sys/mman.h>

// Структура для передачі всієї таблиці L1
typedef struct {
    uint32_t ttbr0;
    uint32_t l1_copy[4096]; // Копія всієї таблиці (16 КБ)
} l1_table_dump_t;

// Тільки "чисте" копіювання пам'яті в Ring 0
void kcall_copy_l1(void *arg) {
    l1_table_dump_t *dump = (l1_table_dump_t *)arg;
    uint32_t temp_ttbr0;

    // Читаємо TTBR0
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(temp_ttbr0));
    dump->ttbr0 = temp_ttbr0;

    // Розраховуємо фізичну адресу таблиці
    // УВАГА: у QNX таблиці зазвичай відображені 1:1 в ядрі
    uint32_t *l1_table_ptr = (uint32_t *)(dump->ttbr0 & 0xFFFFC000);

    // Копіюємо 4096 записів (по 4 байти кожен)
    for (int i = 0; i < 4096; i++) {
        dump->l1_copy[i] = l1_table_ptr[i];
    }
}

void analyze_l1(l1_table_dump_t *dump) {
    printf("=== ANALYZING L1 MAP (TTBR0: 0x%08X) ===\n", dump->ttbr0);

    uint32_t start_vaddr = 0;
    int last_type = -1; // 0: Fault, 1: PageTable, 2: Section
    uint32_t last_flags = 0;
    uint32_t last_paddr = 0;

    for (int i = 0; i <= 4096; i++) {
        uint32_t entry = (i < 4096) ? dump->l1_copy[i] : 0xFFFFFFFF; // Термінатор
        uint32_t type = entry & 0x3;
        uint32_t flags = entry & 0xFFF;
        uint32_t paddr = (type == 2) ? (entry & 0xFFF00000) : (entry & 0xFFFFFC00);

        // Якщо регіон змінився — друкуємо попередній
        if (i > 0 && (type != last_type || (type == 2 && (paddr != last_paddr + 0x100000 || flags != last_flags)) || i == 4096)) {
            if (last_type != 0 && last_type != 3) {
                printf("0x%08X - 0x%08X | ", start_vaddr, (i << 20) - 1);
                if (last_type == 2) {
                    printf("PHYS: 0x%08X | Section | AP:%d\n", last_paddr, (last_flags >> 10) & 0x3);
                } else {
                    printf("L2 TABLE AT: 0x%08X\n", last_paddr);
                }
            }
            start_vaddr = i << 20;
        }

        last_type = type;
        last_flags = flags;
        last_paddr = paddr;
    }
}

int main() {
    if (ThreadCtl(_NTO_TCTL_IO, 0) == -1) {
        perror("ThreadCtl");
        return 1;
    }

    // Виділяємо пам'ять під дамп (на стеку може бути забагато)
    l1_table_dump_t *dump = malloc(sizeof(l1_table_dump_t));
    if (!dump) return 1;

    printf("Copying L1 table in Ring 0...\n");
    if (__Ring0(kcall_copy_l1, dump) == -1) {
        perror("__Ring0 failed");
    } else {
        analyze_l1(dump);
    }

    free(dump);
    return 0;
}
