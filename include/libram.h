#ifndef _LIBRAM_H_INCLUDED
#define _LIBRAM_H_INCLUDED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/syspage.h>
#include <sys/mman.h>
#include <sys/syspage.h>
#include <libhash.h>
#define PAGE_SIZE 4096
#define ALIGN_UP(addr, size) (((uintptr_t)(addr) + ((size) - 1)) & ~((uintptr_t)(size) - 1))

/**
 * Finds the start address and size of a specific memory region in asinfo.
 * * @param region_name The name of the region to search for (e.g., "1to1").
 * @param start_addr  Pointer to store the start address.
 * @param size        Pointer to store the calculated size (end - start + 1).
 * @return 0 on success, -1 if the region was not found.
 */
int get_asinfo_region(const char *name, uint32_t *addr, uint32_t *size)
{
    /* Отримуємо вказівник на масив asinfo_entry */
    struct asinfo_entry *as = SYSPAGE_ENTRY(asinfo);

    /* Отримуємо вказівник на секцію strings та приводимо до правильного типу */
    struct strings_entry *s_entry = _SYSPAGE_ENTRY(_syspage_ptr, strings);
    char *as_strings = s_entry->data;

    /* Розраховуємо кількість елементів.
       Оскільки len немає, використовуємо загальний розмір системної сторінки як ліміт */
    unsigned total_size = _syspage_ptr->total_size;
    unsigned as_off = _syspage_ptr->asinfo.entry_off;

    /* Максимально можлива кількість записів у залишку системної сторінки */
    int max_entries = (total_size - as_off) / sizeof(struct asinfo_entry);

    for (int i = 0; i < max_entries; i++)
    {
        /* Перевіряємо, чи ми не вийшли за межі пам'яті або чи не зустрівся порожній запис */
        if (as[i].name == AS_NULL_OFF)
        {
            break;
        }

        /* Отримуємо ім'я регіону */
        const char *entry_name = &as_strings[as[i].name];

        if (strcmp(entry_name, name) == 0)
        {
            if (addr)
                *addr = as[i].start;
            if (size)
                *size = (as[i].end - as[i].start) + 1;
            return 0;
        }
    }

    return -1;
}

typedef struct
{
    uint32_t addr;
    uint32_t size;
} region_t;

/**
 * Finds all memory regions with a given name.
 * * @param name         The name of the region to search for.
 * @param found_count  Pointer to an integer to store the number of regions found.
 * @return             Allocated array of region_t or NULL if nothing found or error.
 * Note: Caller must free() the returned pointer.
 */
region_t *get_asinfo_regions(const char *name, int *found_count)
{
    struct asinfo_entry *as = SYSPAGE_ENTRY(asinfo);
    char *as_strings = _SYSPAGE_ENTRY(_syspage_ptr, strings)->data;
    int total_entries = _syspage_ptr->asinfo.entry_size / sizeof(struct asinfo_entry);

    region_t *results = NULL;
    int count = 0;

    /* Перший прохід: рахуємо кількість збігів */
    for (int i = 0; i < total_entries; i++)
    {
        if (strcmp(&as_strings[as[i].name], name) == 0)
        {
            count++;
        }
    }

    if (count > 0)
    {
        results = malloc(sizeof(region_t) * count);
        if (results == NULL)
            return NULL;

        int idx = 0;
        /* Другий прохід: заповнюємо масив даними */
        for (int i = 0; i < total_entries; i++)
        {
            if (strcmp(&as_strings[as[i].name], name) == 0)
            {
                results[idx].addr = as[i].start;
                results[idx].size = (as[i].end - as[i].start) + 1;
                idx++;
            }
        }
    }

    if (found_count)
        *found_count = count;
    return results;
}

int read_phys_fd(int memfd, uint32_t phys_addr, void *data, size_t len)
{
    uint32_t page_base = phys_addr & ~(uint32_t)(PAGE_SIZE - 1);
    uint32_t page_off = phys_addr & (uint32_t)(PAGE_SIZE - 1);
    size_t map_len = page_off + len;

    void *map = mmap(NULL, map_len,
                     PROT_READ, MAP_SHARED,
                     memfd, (off_t)page_base);
    if (map == MAP_FAILED)
        return -1;

    memcpy(data, (uint8_t *)map + page_off, len);
    munmap(map, map_len);
    return 0;
}

int write_phys_fd(int memfd, uint32_t phys_addr, const void *data, size_t len)
{
    uint32_t page_base = phys_addr & ~(uint32_t)(PAGE_SIZE - 1);
    uint32_t page_off = phys_addr & (uint32_t)(PAGE_SIZE - 1);
    size_t map_len = page_off + len;

    void *map = mmap(NULL, map_len,
                     PROT_READ | PROT_WRITE, MAP_SHARED,
                     memfd, (off_t)page_base);
    if (map == MAP_FAILED)
        return -1;

    memcpy((uint8_t *)map + page_off, data, len);
    msync(map, map_len, MS_SYNC);
    munmap(map, map_len);
    return 0;
}

int read_phys(uintptr_t phys_addr, void *data, size_t len)
{
    void *map = mmap(NULL, len, PROT_READ, MAP_PHYS | MAP_SHARED, NOFD, phys_addr);

    if (map == MAP_FAILED)
    {
        return -1;
    }

    memcpy(data, map, len);
    munmap(map, len);
    return 0;
}

int write_phys(uintptr_t phys_addr, const void *data, size_t len)
{
    void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PHYS | MAP_SHARED, NOFD, phys_addr);

    if (map == MAP_FAILED)
    {
        return -1;
    }

    memcpy(map, data, len);
    msync(map, len, MS_SYNC);
    munmap(map, len);
    return 0;
}

int patchRAMDword_fd(int memfd, int addr, uint32_t old, uint32_t new)
{
    uint32_t val = -1;
    if (!read_phys_fd(memfd, addr, &val, sizeof(val)))
    {
        if (old == val)
        {
            if (!write_phys_fd(memfd, addr, &new, sizeof(new)))
            {
                return 0;
            }
            else
            {
                return 1;
            }
        }
        else if (new == val)
        {
            return 0;
        }
        else
        {
            return 2;
        }
    }
    else
    {
        return 3;
    }
}

int patchRAMDword(int addr, uint32_t old, uint32_t new)
{
    uint32_t val = -1;
    if (!read_phys(addr, &val, sizeof(val)))
    {
        if (old == val)
        {
            if (!write_phys(addr, &new, sizeof(new)))
            {
                return 0;
            }
            else
            {
                return 1;
            }
        }
        else if (new == val)
        {
            return 0;
        }
        else
        {
            return 2;
        }
    }
    else
    {
        return 3;
    }
}

typedef uint32_t DWORD;

/**
 * Searches for a DWORD and returns its byte offset.
 * * @param buffer Pointer to the data.
 * @param buffer_size Size of the buffer.
 * @param target The 4-byte value to find.
 * @return The zero-based offset, or -1 if not found.
 */
long find_dword_offset(const uint8_t *buffer, size_t buffer_size, DWORD target)
{
    if (buffer == NULL || buffer_size < sizeof(DWORD))
    {
        return -1;
    }

    // Extract the first byte of the target for memchr optimization
    // (Assuming target is in native endianness)
    uint8_t first_byte = (uint8_t)(target & 0xFF);
    const uint8_t *current_pos = buffer;
    size_t remaining_size = buffer_size;

    while (remaining_size >= sizeof(DWORD))
    {
        // Fast search for the first byte of our DWORD
        const uint8_t *match = memchr(current_pos, first_byte, remaining_size - sizeof(DWORD) + 1);

        if (match == NULL)
        {
            break; // First byte not found at all
        }

        // Check if the next 3 bytes also match
        DWORD candidate;
        memcpy(&candidate, match, sizeof(DWORD));

        if (candidate == target)
        {
            return (long)(match - buffer); // Calculate and return offset
        }

        // Move forward by 1 byte and search again
        size_t consumed = (size_t)(match - current_pos) + 1;
        current_pos += consumed;
        remaining_size -= consumed;
    }

    return -1; // Not found
}
#endif