#ifndef _SIGNATURE_H_INCLUDED
#define _SIGNATURE_H_INCLUDED
#include <stddef.h>
#include <string.h>

void find_signatures(const unsigned char *data, size_t data_len)
{
    // SIG_COUNT та db вже визначені в signatures.h
    for (size_t i = 0; i < data_len; i++)
    {
        for (size_t j = 0; j < SIG_COUNT; j++)
        {
            if (i + db[j].len > data_len)
                continue;

            bool match = true;
            for (size_t k = 0; k < db[j].len; k++)
            {
                if (db[j].mask[k] && data[i + k] != db[j].pattern[k])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                if (!db[j].found)
                    db[j].found_offset = i;
                db[j].found++;
            }
        }
    }
}
/**
 * Шукає запис у базі даних за ім'ям.
 * Повертає вказівник на структуру Signature або NULL, якщо нічого не знайдено.
 */
Signature* find_signature_by_name(const char* name) {
    if (name == NULL) {
        return NULL;
    }

    // Обчислюємо кількість елементів у статичному масиві db
    size_t db_size = sizeof(db) / sizeof(db[0]);

    for (size_t i = 0; i < db_size; i++) {
        // Перевіряємо, чи збігається ім'я
        if (db[i].name != NULL && strcmp(db[i].name, name) == 0) {
            return &db[i];
        }
    }

    return NULL; // Запис не знайдено
}
#endif