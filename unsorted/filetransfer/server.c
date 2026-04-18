#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // Про всяк випадок для специфічних опцій TCP
#include "protocol.h"

int read_full(int sock, void *buf, size_t size)
{
    size_t received = 0;
    char *ptr = (char *)buf;
    while (received < size)
    {
        ssize_t n = recv(sock, ptr + received, size - received, 0);
        if (n <= 0)
            return -1; // Помилка або закриття сокета
        received += n;
    }
    return 0;
}

void handle_get(int client_sock, struct file_header *req)
{
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "/tmp/%s", req->name);

    FILE *fp = fopen(filepath, "rb");
    if (!fp)
    {
        struct file_header err = {.command = CMD_ERROR};
        send(client_sock, &err, sizeof(err), 0);
        return;
    }

    fseek(fp, 0, SEEK_END);
    uint32_t fsize = ftell(fp);
    rewind(fp);

    unsigned char *data = malloc(fsize);
    fread(data, 1, fsize, fp);
    fclose(fp);

    struct file_header res;
    res.command = CMD_GET;
    res.size = fsize;
    res.crc32 = calculate_crc32(data, fsize);
    strncpy(res.name, req->name, MAX_FILENAME);

    send(client_sock, &res, sizeof(res), 0);
    send(client_sock, data, fsize, 0);
    free(data);
}

void handle_put(int client_sock, struct file_header *req)
{
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "/tmp/%s", req->name);

    FILE *fp = fopen(filepath, "wb");
    unsigned char *full_data = malloc(req->size);

    uint32_t received = 0;
    int n;
    while (received < req->size && (n = recv(client_sock, full_data + received, 4096, 0)) > 0)
    {
        received += n;
    }

    fwrite(full_data, 1, req->size, fp);
    fclose(fp);

    // Перевірка CRC
    uint32_t local_crc = calculate_crc32(full_data, req->size);
    if (local_crc == req->crc32)
    {
        printf("[QNX] OK: %s отримано. CRC збігається.\n", req->name);
        chmod(filepath, (!req->mode) ? 0777 : req->mode); // Встановлюємо права
    }
    else
    {
        printf("[QNX] ERROR: Помилка CRC для %s! (Очікували: %X, Отримали: %X)\n",
               req->name, req->crc32, local_crc);
        remove(filepath); // Видаляємо битий файл
    }

    free(full_data);
}

int main()
{
    int server_fd, client_sock;
    struct sockaddr_in addr;
    int opt = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("[QNX] Готовий до прийому файлів...\n");

    while (1)
    {
        client_sock = accept(server_fd, NULL, NULL);
        struct file_header header;

        // Гарантовано читаємо весь заголовок
        if (read_full(client_sock, &header, sizeof(header)) == 0)
        {
            printf("DEBUG: CMD=%u, Name=%s, Size=%u\n", header.command, header.name, header.size);
            if (header.command == CMD_GET)
            {
                handle_get(client_sock, &header);
            }
            else if (header.command == CMD_PUT)
            {
                handle_put(client_sock, &header);
            }
        }
        else
        {
            printf("[QNX] Помилка отримання заголовка\n");
        }
        close(client_sock);
    }
    return 0;
}