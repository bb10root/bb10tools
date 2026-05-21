/*
 * main.c
 *
 *  Created on: Mar 12, 2025
 *      Author: lc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <getopt.h>

#define BOOTROM_METRICS_SIZE 0x4fc
#define OS_METRICS_SIZE 0x1d4

int (*nv_delete_insecure)(int blockid);
int (*nv_delete_secure)(int blockid);
int (*nv_get_record)(int blockid, void *buff, int size);
int (*nv_write_record)(int blockid, void *buff, int size);
int (*nv_write_secure_record)(int blockid, void *buff, int size);
int (*nv_is_protected)(int blockid);
int (*nv_record_exists)(int blockid);
int (*nv_get_permissions)(int blockid);
int (*GetBootromMetrics)(void *buff);
void * (*readOSMetrics)(void);
void * (*readBootromMetrics)(void);

int load_libnvram()
{
    void *handle;
    handle = dlopen("/proc/boot/libnvram.so.1", RTLD_LAZY);
    if (!handle) {
        /* fail to load the library */
        fprintf(stderr, "Error: %s\n", dlerror());
        return EXIT_FAILURE;
    }

    *(void**) (&nv_delete_insecure) = dlsym(handle, "nv_delete_insecure");
    if (!nv_delete_insecure) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_delete_secure) = dlsym(handle, "nv_delete_secure");
    if (!nv_delete_secure) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_get_record) = dlsym(handle, "nv_get_record");
    if (!nv_get_record) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_write_record) = dlsym(handle, "nv_write_record");
    if (!nv_write_record) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_write_secure_record) = dlsym(handle, "nv_write_secure_record");
    if (!nv_write_secure_record) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_is_protected) = dlsym(handle, "nv_is_protected");
    if (!nv_is_protected) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_record_exists) = dlsym(handle, "nv_record_exists");
    if (!nv_record_exists) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&nv_get_permissions) = dlsym(handle, "nv_get_permissions");
    if (!nv_get_permissions) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&GetBootromMetrics) = dlsym(handle, "GetBootromMetrics");
    if (!GetBootromMetrics) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&readOSMetrics) = dlsym(handle, "readOSMetrics");
    if (!readOSMetrics) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }

    *(void**) (&readBootromMetrics) = dlsym(handle, "readBootromMetrics");
    if (!readBootromMetrics) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return EXIT_FAILURE;
    }
    return 0;
}

/*
 *
 * https://stackoverflow.com/a/2336245
 *
 */
static void _mkdir(const char *dir)
{
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    mkdir(tmp, S_IRWXU);
}
#ifdef ENABLE_UNLOCK
void unlock()
{
    int res, s;
    unsigned char * buff;
    buff = malloc(3096);
    memset(buff, 0, 3096);

    s = nv_get_record(0x2008, buff, 3096);
    memset(buff + 1, 0, 3);
    memset(buff + 0x58, 0, 40);

    res = nv_write_record(0x2008, buff, 3096);

    //memset(buff, 0, 3096);
    //s = nv_get_record(0x285b, buff, 0x76);
    //res = nv_write_record(0x285b, buff, 0x76);
}
#endif
void downgrade()
{
    int res;
    res = nv_delete_insecure(0x2819);
    printf("Delete OS BLOCK done %d\n", res);
    res = nv_delete_secure(0x2819);
    printf("Delete secure OS BLOCK done %d\n", res);

    res = nv_delete_insecure(0x2852);
    printf("Delete RADIO BLOCK done %d\n", res);
    res = nv_delete_secure(0x2852);
    printf("Delete secure RADIO BLOCK done %d\n", res);

}

void backup(char *path)
{
    int i, s;
    FILE * fptr;
    unsigned char * buff;
    char fname[512];
    buff = malloc(60000);

    _mkdir(path);
    for (i = 0; i < 0xFFFF; i++) {

        if (0 != nv_record_exists(i)) {
            s = nv_get_record(i, buff, 1);
            if (s < 60000) {
                memset(buff, 0, s);
                s = nv_get_record(i, buff, s);
                if (0 != nv_is_protected(i)) {
                    sprintf(fname, "%s/nvram_%04X_s.bin", path, i);
                } else {
                    sprintf(fname, "%s/nvram_%04X.bin", path, i);
                }
                fptr = fopen(fname, "wb+");

                if (fptr == NULL) {
                    exit(1);
                }
                fwrite(buff, s, 1, fptr);
                printf("[%04x] Read done \r", i);
                fclose(fptr);

            } else {
                printf("\nRecord %04x too long, %d bytes\n", i, s);
            }

        }

    }
    free(buff);

}

int main(int argc, char* argv[])
{
    if (load_libnvram() == 0) {

        char c;
        while ((c = getopt(argc, argv, "b:du")) != -1) {
            switch (c) {
                case 'b':
                    printf("backup NVRAM blocks to: '%s/'\n", optarg);
                    backup(optarg);
                    printf("Done\n");
                    break;
                case 'u':
#ifdef ENABLE_UNLOCK
                    printf("Unlocking SIM\n");
                    unlock();
                    printf("Done\n");
#else
                    printf("Unsupported\n");

#endif
                    break;
                case 'd':
                    printf("Downgrade FW\n");
                    downgrade();
                    printf("Done\n");
                    break;
            }
        }

    }
    return 0;
}
