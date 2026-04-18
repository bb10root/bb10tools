#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <arpa/inet.h>
#include "protocol.h"

void put_file(const char *path, const char *ip) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("File error"); return; }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    unsigned char *data = malloc(fsize);
    fread(data, 1, fsize, fp);
    fclose(fp);

    struct file_header header;
    header.size = (uint32_t)fsize;
    header.crc32 = calculate_crc32(data, fsize);
    header.command = CMD_PUT;
    header.mode = 0777;
    strncpy(header.name, basename((char*)path), MAX_FILENAME);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        send(sock, &header, sizeof(header), 0);
        send(sock, data, fsize, 0);
        printf("[Linux] Файл %s (CRC: %X) відправлено.\n", header.name, header.crc32);
    }

    free(data);
    close(sock);
}

void get_file(const char *filename, const char *ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) return;

    struct file_header req = {.command = CMD_GET};
    strncpy(req.name, filename, MAX_FILENAME);
    send(sock, &req, sizeof(req), 0);

    struct file_header res;
    if (recv(sock, &res, sizeof(res), 0) <= 0 || res.command == CMD_ERROR) {
        printf("[-] Файл не знайдено на сервері\n");
        close(sock);
        return;
    }

    unsigned char *data = malloc(res.size);
    uint32_t received = 0;
    while (received < res.size) {
        int n = recv(sock, data + received, 4096, 0);
        if (n <= 0) break;
        received += n;
    }

    if (calculate_crc32(data, res.size) == res.crc32) {
        FILE *fp = fopen(res.name, "wb");
        fwrite(data, 1, res.size, fp);
        fclose(fp);
        printf("[+] Файл %s успішно завантажено (CRC OK)\n", res.name);
    } else {
        printf("[-] CRC error!\n");
    }

    free(data);
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Use: %s <IP> <put/get> <file>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[2], "get") == 0) get_file(argv[3], argv[1]);
    if (strcmp(argv[2], "put") == 0) put_file(argv[3], argv[1]);
 
    return 0;
}