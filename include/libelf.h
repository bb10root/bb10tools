#ifndef _LIBELF_H_INCLUDED
#define _LIBELF_H_INCLUDED

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/elf.h>

#define PAGE_SIZE 4096
#define ALIGN_UP(addr, size) (((uintptr_t)(addr) + ((size) - 1)) & ~((uintptr_t)(size) - 1))

#define ELF_MAGIC "\x7f\x45\x4c\x46" // "\x7fELF"

#ifndef DT_NULL
#define DT_NULL 0
#define DT_PLTGOT 3
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELSZ 18
#define DT_REL 17
#define DT_PLTRELSZ 2
#define DT_JMPREL 23

typedef struct
{
    Elf32_Sword d_tag;
    union
    {
        Elf32_Word d_val;
        Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;
#endif

typedef struct
{
    void *map;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Sym *dynsym;
    char *dynstr;
    Elf32_Rel *rel_plt;
    uint32_t plt_vaddr;
    int rel_plt_count;
} elf_ctx_t;

typedef struct
{
    uint8_t *data;
    uint32_t size;
    uint32_t vaddr;
} code_section_t;

static uint32_t _elf_vaddr_to_off(elf_ctx_t *ctx, uint32_t vaddr)
{
    if (!vaddr)
        return 0;
    for (int i = 0; i < ctx->ehdr->e_phnum; i++)
    {
        Elf32_Phdr *p = &ctx->phdr[i];
        if (p->p_type == PT_LOAD && vaddr >= p->p_vaddr && vaddr < p->p_vaddr + p->p_memsz)
        {
            return (vaddr - p->p_vaddr) + p->p_offset;
        }
    }
    return 0;
}

int elf_init_ctx(elf_ctx_t *ctx, void *map)
{
    memset(ctx, 0, sizeof(elf_ctx_t));
    ctx->map = map;
    ctx->ehdr = (Elf32_Ehdr *)map;
    ctx->phdr = (Elf32_Phdr *)(map + ctx->ehdr->e_phoff);

    Elf32_Dyn *dyn = NULL;
    uint32_t jmprel_vaddr = 0;
    uint32_t pltgot_vaddr = 0;

    // 1. Пошук Dynamic Segment
    for (int i = 0; i < ctx->ehdr->e_phnum; i++)
    {
        if (ctx->phdr[i].p_type == PT_DYNAMIC)
        {
            dyn = (Elf32_Dyn *)(map + ctx->phdr[i].p_offset);
            break;
        }
    }
    if (!dyn)
        return -1;

    // 2. Збір даних з Dynamic секції
    for (; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
        case DT_STRTAB:
            ctx->dynstr = (char *)(map + _elf_vaddr_to_off(ctx, dyn->d_un.d_ptr));
            break;
        case DT_SYMTAB:
            ctx->dynsym = (Elf32_Sym *)(map + _elf_vaddr_to_off(ctx, dyn->d_un.d_ptr));
            break;
        case DT_JMPREL:
            jmprel_vaddr = dyn->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            ctx->rel_plt_count = dyn->d_un.d_val / sizeof(Elf32_Rel);
            break;
        case DT_PLTGOT:
            pltgot_vaddr = dyn->d_un.d_ptr;
            break;
        }
    }

    if (jmprel_vaddr)
    {
        ctx->rel_plt = (Elf32_Rel *)(map + _elf_vaddr_to_off(ctx, jmprel_vaddr));
    }

    // 3. ПОШУК PLT БЕЗ СЕКЦІЙ (для ARM QNX)
    // На ARM адреса PLT часто йде відразу після заголовків або її можна вирахувати
    // через релокації. Найчастіше PLT знаходиться за адресою першої релокації - 20 байт.
    if (ctx->rel_plt_count > 0 && ctx->rel_plt)
    {
        // Емпіричний метод для QNX ARM: PLT зазвичай знаходиться в межах першого LOAD
        // Ми спробуємо знайти її за адресою, куди посилаються релокації,
        // але зазвичай на ARM PLT vaddr можна знайти, віднявши заголовок від першого запису.
        // Більш надійно: шукаємо сегмент LOAD з R-X прапорцями.
        for (int i = 0; i < ctx->ehdr->e_phnum; i++)
        {
            if (ctx->phdr[i].p_type == PT_LOAD && (ctx->phdr[i].p_flags & PF_X))
            {
                // В ARM QNX .plt часто починається за адресою 0x1000 або подібною.
                // Якщо ми не маємо точної адреси, можна спробувати знайти її через DT_JMPREL
                // Але зазвичай PLT vaddr == jmprel_vaddr - (щось).
                // Спробуємо автоматично визначити через зміщення релокацій:
                ctx->plt_vaddr = jmprel_vaddr - 4; // Спрощений підхід для ARM
            }
        }
    }

    // Якщо нічого не допомогло, і ми знаємо, що LOAD починається з 0x0:
    if (ctx->plt_vaddr < 0x100)
    {
        // Шукаємо сигнатуру PLT в пам'яті (ARM PLT[0] починається з певних інструкцій)
        // Для QNX ARM це зазвичай: STR lr, [sp, #-4]!
        uint32_t *p = (uint32_t *)map;
        for (int i = 0; i < 0x2000; i++)
        {
            if (p[i] == 0xe52de004)
            { // Сигнатура ARM PLT header
                ctx->plt_vaddr = i * 4;
                break;
            }
        }
    }

    return 0;
}

code_section_t elf_get_text(elf_ctx_t *ctx)
{
    code_section_t section = {NULL, 0, 0};
    for (int i = 0; i < ctx->ehdr->e_phnum; i++)
    {
        if (ctx->phdr[i].p_type == PT_LOAD && (ctx->phdr[i].p_flags & PF_X))
        {
            section.data = (uint8_t *)(ctx->map + ctx->phdr[i].p_offset);
            section.size = ctx->phdr[i].p_filesz;
            section.vaddr = ctx->phdr[i].p_vaddr;
            break;
        }
    }
    return section;
}

uint32_t elf_get_plt_entry(elf_ctx_t *ctx, const char *func_name)
{
    if (!ctx->dynsym || !ctx->rel_plt || !ctx->dynstr)
        return 0;

    // 1. Знайти релокацію для нашої функції
    int sym_idx = -1;
    for (int i = 0; i < 5000; i++)
    {
        if (ctx->dynsym[i].st_name && strcmp(ctx->dynstr + ctx->dynsym[i].st_name, func_name) == 0)
        {
            sym_idx = i;
            break;
        }
    }
    if (sym_idx == -1)
        return 0;

    int rel_idx = -1;
    for (int i = 0; i < ctx->rel_plt_count; i++)
    {
        if (ELF32_R_SYM(ctx->rel_plt[i].r_info) == (uint32_t)sym_idx)
        {
            rel_idx = i;
            break;
        }
    }
    if (rel_idx == -1)
        return 0;

    // 2. Універсальний збір ВСІХ адрес PLT записів
    // Створюємо динамічний список адрес
    static uint32_t *plt_entries = NULL;
    static int found_count = 0;

    if (plt_entries == NULL)
    {
        plt_entries = malloc(ctx->rel_plt_count * sizeof(uint32_t));
        code_section_t text = elf_get_text(ctx);
        uint32_t *ptr = (uint32_t *)text.data;

        for (uint32_t i = 0; i < text.size / 4 - 2; i++)
        {
            // Шукаємо сигнатуру ADR R12 (початок будь-якого запису)
            if ((ptr[i] & 0xFFFFF000) == 0xE28FC000)
            {
                if (found_count < ctx->rel_plt_count)
                {
                    plt_entries[found_count++] = text.vaddr + (i * 4);
                }
            }
        }
    }

    // 3. Повертаємо адресу за індексом релокації
    if (rel_idx < found_count)
    {
        return plt_entries[rel_idx];
    }

    return 0;
}

// Use the xxHash32_Universal function we discussed earlier
uint32_t xxHash32_Universal(const void *input, size_t len, uint32_t seed);

/**
 * Find an ELF block by comparing its header and xxHash
 * @param start_addr Address to begin search
 * @param end_addr   Address to end search
 * @param target_hash Precomputed hash of the target ELF header (or block)
 * @return Pointer to the found ELF or NULL
 */
void *find_elf_in_memory(const void *start_addr, const void *end_addr, uint32_t target_hash)
{
    const uint8_t *current = (const uint8_t *)ALIGN_UP(start_addr, PAGE_SIZE);
    const uint8_t *end = (const uint8_t *)end_addr;

    // Ensure we start aligned
    current = (const uint8_t *)(((uintptr_t)current + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

    while (current + PAGE_SIZE <= end)
    {
        // 1. Fast check: Magic Number (most candidates fail here instantly)
        if (memcmp(current, ELF_MAGIC, 4) == 0)
        {

            // 2. Secondary check: Hash of the first 256 bytes (contains header & program headers)
            // This is much faster than hashing a multi-megabyte file
            if (xxHash32_Universal(current, 256, 0) == target_hash)
            {

                // Optional: Final verify with memcmp or more complex logic
                return (void *)current;
            }
        }

        // Skip exactly one page
        current += PAGE_SIZE;
    }

    return NULL;
}
#endif