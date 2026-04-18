#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#define LOG_DIR "/tmp/logs"
#define MAX_SCRIPTS 128

const char *config_search_paths[] = {
    "/var/etc/autostart.conf",
    "/accounts/devuser/autostart.conf",
    "/accounts/1000/autostart.conf",
    NULL
};

char *executed_scripts[MAX_SCRIPTS];
int executed_count = 0;

// Функція очищення рядка: видаляє коментарі та пробіли з обох боків
char *trim_and_strip_comment(char *str) {
    char *end;
    char *comment = strchr(str, '#');
    if (comment) *comment = '\0';

    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

int is_duplicate(const char *path) {
    for (int i = 0; i < executed_count; i++) {
        if (strcmp(executed_scripts[i], path) == 0) return 1;
    }
    return 0;
}

void spawn_script(const char *path) {
    if (executed_count < MAX_SCRIPTS) {
        executed_scripts[executed_count++] = strdup(path);
    }

    pid_t pid = fork();
    if (pid != 0) return;

    setsid();
    umask(0);
    mkdir(LOG_DIR, 0777);

    char path_copy[1024];
    strncpy(path_copy, path, sizeof(path_copy));
    char *script_name = basename(path_copy);

    char log_full_path[1024];
    snprintf(log_full_path, sizeof(log_full_path), "%s/%s.log", LOG_DIR, script_name);

    int fd = open(log_full_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd != -1) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    int dev_null = open("/dev/null", O_RDONLY);
    dup2(dev_null, STDIN_FILENO);

    execl("/bin/sh", "sh", "-c", path, (char *)NULL);
    _exit(EXIT_FAILURE);
}

#define APP_NAME "BB10 autorun tool"
#define APP_VERSION "1.0.0"

#include <banner.h>

int main(void) {
    display_system_banner();
    char line[1024];
    printf("Autostart Manager: Starting (Trim & Comments enabled)...\n");

    for (int i = 0; config_search_paths[i] != NULL; i++) {
        const char *conf = config_search_paths[i];
        if (access(conf, R_OK) != 0) continue;

        FILE *fp = fopen(conf, "r");
        if (!fp) continue;

        printf("Processing: %s\n", conf);

        while (fgets(line, sizeof(line), fp)) {
            // Обробляємо рядок: прибираємо коментарі та пробіли
            char *clean_path = trim_and_strip_comment(line);

            // Пропускаємо порожні рядки
            if (strlen(clean_path) == 0) continue;

            if (is_duplicate(clean_path)) {
                printf("  [SKIP] Duplicate: %s\n", clean_path);
                continue;
            }

            if (access(clean_path, X_OK) == 0) {
                printf("  [EXEC] %s\n", clean_path);
                spawn_script(clean_path);
            } else {
                fprintf(stderr, "  [ERR] Not executable: '%s'\n", clean_path);
            }
        }
        fclose(fp);
    }

    printf("Manager: Done. Total unique scripts: %d\n", executed_count);
    return EXIT_SUCCESS;
}
