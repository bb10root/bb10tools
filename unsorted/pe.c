/*
 * pe.c
 *
 * bb10 processes enumerator & dumper
 * 
 *  Created on: Jan 11, 2026
 *      Author: lc
 */
/* libc / POSIX */
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

/* types */
#include <sys/types.h>

/* QNX / Neutrino */
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/procmsg.h>
#include <sys/mman.h>
#include <sys/syspage.h>
#include <sys/debug.h>

/* network */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* project / local */
#include "procmgr.h"

int server;

int pid_str_to_int(const char *pid_str)
{
    long v;
    char *end;

    if (!pid_str || !*pid_str)
        return -1;

    errno = 0;
    v = strtol(pid_str, &end, 10);

    if (errno || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;

    return (int)v;
}

#define MSG_MAGIC 0x50454455  /* "PEDU" */

enum {
    MSG_META   = 1,
    MSG_SEG    = 2,
    MSG_LOG    = 3,
    MSG_DONE   = 0xFF
};

typedef struct {
    uint32_t magic;    // "PEDU"
    uint16_t type;
    uint16_t version;  // protocol version
    uint32_t length;
} __attribute__((packed)) msg_hdr_t;

typedef struct {
    uint32_t pid;
    uint64_t vaddr;
    uint64_t size;
    uint32_t flags;
    uint32_t dev;
    uint64_t ino;
} __attribute__((packed)) msg_map_t;

typedef struct {
    uint32_t pid;       // pid процесу
    char     text[1024]; // повідомлення
} __attribute__((packed)) msg_log_t;


static int writen(int fd, const void *buf, size_t len)
{
    size_t off = 0;
    const char *p = buf;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n <= 0)
            return -1;
        off += n;
    }
    return 0;
}


int send_msg(int sock, uint16_t type, const void *buf, uint32_t len)
{
    msg_hdr_t h;

    h.magic   = htonl(MSG_MAGIC);
    h.type    = htons(type);
    h.version = htons(1);
    h.length  = htonl(len);

    if (writen(sock, &h, sizeof(h)) < 0)
        return -1;

    if (len && writen(sock, buf, len) < 0)
        return -1;
    
    return 0;
}

int send_log(int sock, int pid, const char *fmt, ...)
{
    msg_log_t log;
    va_list ap;

    log.pid = htonl(pid);  // зберігаємо pid у мережевому порядку

    va_start(ap, fmt);
    int n = vsnprintf(log.text, sizeof(log.text), fmt, ap);
    va_end(ap);

    if (n < 0) return -1;
    if ((size_t)n >= sizeof(log.text)) log.text[sizeof(log.text) - 1] = '\0';

    return send_msg(sock, MSG_LOG, &log, sizeof(log.pid) + strlen(log.text));
}


void dump_mem_stream(int proc_fd,
                     const procfs_mapinfo *m,
                     int sock,
                     pid_t pid)
{
    msg_map_t seg_hdr;

    unsigned char buf[64*1024];
    uint64_t off = 0;

    seg_hdr.pid   = htonl(pid);
    seg_hdr.vaddr = htobe64(m->vaddr);
    seg_hdr.size  = htobe64(m->size);

    seg_hdr.flags = htonl(m->flags);
    seg_hdr.dev   = htonl(m->dev);
    seg_hdr.ino   = htobe64(m->ino);

    send_msg(sock, MSG_SEG, &seg_hdr, sizeof(msg_map_t));

    while (off < m->size) {
        size_t n = m->size - off;
        if (n > sizeof(buf)) n = sizeof(buf);

        ssize_t r = pread64(proc_fd, buf, n, m->vaddr + off);
        if (r <= 0)
            break;

        if (writen(sock, buf, r) < 0)
            break;

        off += r;
    }
}

static int proc_stop(int fd)
{
    return devctl(fd, DCMD_PROC_STOP, NULL, 0, NULL);
}

static int proc_run(int fd)
{
    return devctl(fd, DCMD_PROC_RUN, NULL, 0, NULL);
}


char *flags_to_str(uint flags)
{
    static char buf[512];
    char *p = buf;

    *p = '\0';

#define ADD(f, s) do { \
    if (flags & (f)) { \
        p += sprintf(p, " %s", (s)); \
    } \
} while (0)

    if ((flags & MAP_PRIVATEANON) == MAP_PRIVATEANON)
        ADD(MAP_PRIVATEANON, "MAP_PRIVATEANON");
    else if (flags & MAP_SHARED)
        ADD(MAP_SHARED, "MAP_SHARED");
    else if (flags & MAP_PRIVATE)
        ADD(MAP_PRIVATE, "MAP_PRIVATE");

#if defined(__EXT_UNIX_HIST)
    ADD(MAP_NORESERVE, "MAP_NORESERVE");
    ADD(MAP_RENAME,    "MAP_RENAME");
#endif

    ADD(MAP_FIXED,      "MAP_FIXED");
    ADD(MAP_ELF,        "MAP_ELF");
    ADD(MAP_NOSYNCFILE, "MAP_NOSYNCFILE");
    ADD(MAP_LAZY,       "MAP_LAZY");
    ADD(MAP_STACK,      "MAP_STACK");
    ADD(MAP_BELOW,      "MAP_BELOW");
    ADD(MAP_NOINIT,     "MAP_NOINIT");
    ADD(MAP_PHYS,       "MAP_PHYS");
    ADD(MAP_NOX64K,     "MAP_NOX64K");
    ADD(MAP_BELOW16M,   "MAP_BELOW16M");
    ADD(MAP_ANON,       "MAP_ANON");

    ADD(MAP_SYSRAM,     "MAP_SYSRAM");
    ADD(MAP_CONSTRAINED,"MAP_CONSTRAINED");
    ADD(MAP_SPARE1,     "MAP_SPARE1");
    ADD(MAP_SPARE2,     "MAP_SPARE2");
    ADD(MAP_SPARE3,     "MAP_SPARE3");
    ADD(MAP_SPARE4,     "MAP_SPARE4");

    ADD(PG_MODIFIED,    "PG_MODIFIED");
    ADD(PG_REFERENCED,  "PG_REFERENCED");
    ADD(PG_HWMAPPED,    "PG_HWMAPPED");

    ADD(PROT_READ,      "PROT_READ");
    ADD(PROT_WRITE,     "PROT_WRITE");
    ADD(PROT_EXEC,      "PROT_EXEC");
    ADD(PROT_NOCACHE,   "PROT_NOCACHE");

    if (!(flags & PROT_MASK))
        p += sprintf(p, " PROT_NONE");

#undef ADD
    return buf;
}

static int is_dumpable(const procfs_mapinfo *m)
{
    if (!(m->flags & PROT_READ))
        return 0;

//    if (m->flags & MAP_PHYS)
//        return 0;

    if (m->size == 0)
        return 0;

    return 1;
}

#define MAX_SEGMENTS 2*1024
#define MAX_THREADS 512

void dump_procfs_info(int fd, int pid)
{
    procfs_info info;
    procfs_status status;
    int sts;

    sts = devctl(fd, DCMD_PROC_INFO, &info, sizeof(info), NULL);
    if (sts != EOK) {
        fprintf(stderr, "DCMD_PROC_INFO pid %d error %d (%s)\n", pid, sts, strerror(sts));
        exit(EXIT_FAILURE);
    }

// structure is now full, and can be printed, analyzed, etc.
    send_log(server, pid, "Process ID: %d\n", pid);
    send_log(server, pid, " uid  : %d", info.uid);
    send_log(server, pid, " gid  : %d\n", info.gid);
    send_log(server, pid, " euid : %d", info.euid);
    send_log(server, pid, " egid : %d\n", info.egid);
    send_log(server, pid, " suid : %d", info.suid);
    send_log(server, pid, " sgid : %d\n", info.sgid);
}

#define DUMP_CHUNK (64*1024)

void dump_mem(int fd, const procfs_mapinfo *m, pid_t pid)
{
    char fname[128];
    int out;
    uint64_t off = 0;
    unsigned char buf[DUMP_CHUNK];

    sprintf(fname, "/tmp/dump_%d_%08llX.bin", pid, m->vaddr);
    out = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (out < 0) return;

    while (off < m->size) {
        size_t toread = (m->size - off > DUMP_CHUNK) ? DUMP_CHUNK : (m->size - off);
        ssize_t r = pread64(fd, buf, toread, m->vaddr + off);
        if (r <= 0) break;
        write(out, buf, r);
        off += r;
    }

    close(out);
}

void dump_procfs_map_info(int fd, int pid)
{

// fetch information about the memory regions for this pid

    procfs_mapinfo *membufs;
    procfs_status my_status;

    int threads_count = 0;
    procfs_greg *old_greg;
    procfs_greg my_greg;

    int size, j;

    int nmembuf;
    int i;
    int sts;
    int res;
    int target = 0;
    int new_sp, new_ip;
    _Uint64t tsize = 0, taddr = 0;
    unsigned char *xbuff;

    membufs = malloc(sizeof(procfs_mapinfo) * MAX_SEGMENTS);
    if (!membufs) {
        printf("membufs alloc error");
        return;
    }
    old_greg = malloc(sizeof(procfs_greg) * MAX_THREADS);
    if (!old_greg) {
        printf("gregs alloc error");
        return;
    }

    printf("DCMD_PROC_MAPINFO\n");
    sts = devctl(fd, DCMD_PROC_MAPINFO, membufs, sizeof(procfs_mapinfo) * MAX_SEGMENTS, &nmembuf);
    if (sts != EOK) {
        fprintf(stderr, "DCMD_PROC_MAPINFO process %d, error %d (%s)\n", pid, sts, strerror(sts));
        return;
    }
    send_log(server, pid, "PAGEDATA ok (%d)\n", nmembuf);

// check to see we haven't overflowed
    if (nmembuf > MAX_SEGMENTS) {
        fprintf(stderr, "proc %d has > %d memsegs (%d)!!!\n", pid, MAX_SEGMENTS, nmembuf);
        return;
    }

    send_log(server, pid, "Buff# --vaddr--- ---size--- ---dev---- ---ino---- ---flags--\n");
    char *flags;
    for (i = 0; i < nmembuf; i++) {
        flags = flags_to_str(membufs[i].flags);
        send_log(server, pid, "[%3d] 0x%08llX 0x%08llX 0x%08X 0x%08llX %s\n", i, membufs[i].vaddr, membufs[i].size,
                membufs[i].dev, membufs[i].ino, flags);
        if (is_dumpable(&membufs[i]))
            dump_mem_stream(fd, &membufs[i], server, pid);
    }

    memset(&my_status, 0, sizeof(my_status));

    for (my_status.tid = 1;
    EOK == devctl(fd, DCMD_PROC_TIDSTATUS, &my_status, sizeof(my_status), 0); my_status.tid++) {

        devctl(fd, DCMD_PROC_CURTHREAD, &my_status.tid, sizeof(my_status.tid), 0);
        devctl(fd, DCMD_PROC_GETGREG, &my_greg, sizeof(procfs_greg), &size);
        send_log(server, pid, "Thread %d\n", threads_count);

        memcpy(&old_greg[threads_count], &my_greg, sizeof(procfs_greg));

        for (i = 0; i < 5; i++)
            send_log(server, pid, "R%d : 0x%08X ", i, my_greg.arm.gpr[i]);
//        send_log(server, pid, "\n");
        for (i = 5; i < 10; i++)
            send_log(server, pid, "R%d : 0x%08X ", i, my_greg.arm.gpr[i]);
//        send_log(server, pid, "\n");
        for (i = 10; i < 15; i++)
            send_log(server, pid, "R%d: 0x%08X ", i, my_greg.arm.gpr[i]);
        send_log(server, pid, "\nPC: %08X\n", my_greg.arm.gpr[15]);
        threads_count++;
    }

    free(old_greg);
    free(membufs);
}

void iterate_process(int pid, char** argv)
{
    char paths[PATH_MAX];
    int fd;
    
     static struct
     {
     procfs_debuginfo info;
     char buff[PATH_MAX];
     } name;     

    sprintf(paths, "/proc/%d/as", pid);

    if ((fd = open64(paths, O_RDWR | O_NONBLOCK)) == -1) {
        // printf("Can't open '%s' for RW!\n", paths);
        return;
    }

    if (devctl(fd, DCMD_PROC_MAPDEBUG_BASE, &name, sizeof(name), 0) != EOK) {
       if (pid == 1) {
          strcpy(name.info.path, "(procnto)");
       } else {
          strcpy(name.info.path, "(n/a)");
       }
    }
    send_log(server, pid, "user: %s\n", argv[0]);
    send_log(server, pid, "exec: %s\n", name.info.path);

    proc_stop(fd);
    dump_procfs_info(fd, pid);
    dump_procfs_map_info(fd, pid);
    proc_run(fd);
    close(fd);
}

int get_pid_list_less_than(
        int max_pid,
        int *pid_list,
        int max_items)
{
    DIR *d;
    struct dirent *ent;
    int count = 0;

    d = opendir("/proc");
    if (!d)
        return -1;

    while ((ent = readdir(d)) != NULL) {
        long pid;
        char *end;

        /* швидкий фільтр */
        if ((unsigned)(ent->d_name[0] - '0') > 9)
            continue;

        errno = 0;
        pid = strtol(ent->d_name, &end, 10);
        if (errno || *end != '\0')
            continue;

        if (pid <= 0 || pid >= max_pid)
            continue;

        pid_list[count++] = (int)pid;

        if (count >= max_items)
            break;
    }

    closedir(d);
    return count;
}


int tcp_connect(const char *host, int port)
{
    int s;
    struct sockaddr_in sa;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(s);
        return -1;
    }

    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(s);
        return -1;
    }
    return s;
}


int main(int argc, char** argv)
{
    #define MAX_PIDS 512
    int pids[MAX_PIDS];


    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t pid = getpid();

    uid_t euid = geteuid();
    gid_t egid = getegid();

    int i, k, res;

    int plain[] = { PROCMGR_AID_SPAWN_SETUID, PROCMGR_AID_SPAWN_SETGID, PROCMGR_AID_SETUID,
    PROCMGR_AID_SETGID, PROCMGR_AID_GETID, PROCMGR_AID_PATHSPACE, PROCMGR_AID_REBOOT,
    PROCMGR_AID_CPUMODE,
    PROCMGR_AID_CONFSET, PROCMGR_AID_RSRCDBMGR, PROCMGR_AID_UMASK,
    PROCMGR_AID_MEM_SPECIAL,
    PROCMGR_AID_MEM_GLOBAL, PROCMGR_AID_SPAWN, PROCMGR_AID_FORK, PROCMGR_AID_V86,
    PROCMGR_AID_QNET, PROCMGR_AID_KEYDATA, PROCMGR_AID_IO, PROCMGR_AID_TRACE,
    PROCMGR_AID_CONNECTION, PROCMGR_AID_SCHEDULE, PROCMGR_AID_PATH_TRUST,
    PROCMGR_AID_SWAP,
    PROCMGR_AID_RCONSTRAINT, PROCMGR_AID_CHILD_NEWAPP, PROCMGR_AID_PUBLIC_CHANNEL,
    PROCMGR_AID_APS_ROOT,
    PROCMGR_AID_ABLE_CREATE, PROCMGR_AID_DEFAULT_TIMER_TOLERANCE };
    int range[] = {
            //PROCMGR_AID_SPAWN_SETUID, PROCMGR_AID_SPAWN_SETGID, PROCMGR_AID_SETUID, PROCMGR_AID_SETGID,
            PROCMGR_AID_RUNSTATE, PROCMGR_AID_SESSION, PROCMGR_AID_EVENT, PROCMGR_AID_RLIMIT,
            PROCMGR_AID_MEM_ADD, PROCMGR_AID_MEM_PHYS, PROCMGR_AID_MEM_PEER,
            PROCMGR_AID_MEM_LOCK,
            PROCMGR_AID_PROT_EXEC, PROCMGR_AID_WAIT, PROCMGR_AID_CLOCKSET,
            PROCMGR_AID_CLOCKPERIOD,
            PROCMGR_AID_INTERRUPT, PROCMGR_AID_PRIORITY, PROCMGR_AID_SIGNAL, PROCMGR_AID_TIMER,
            PROCMGR_AID_PGRP, PROCMGR_AID_MAP_FIXED, PROCMGR_AID_RUNSTATE_BURST };

    k = sizeof(plain) / 4;
    for (i = 0; i < k; i++) {
        res = procmgr_ability(pid,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_INHERIT_YES | PROCMGR_AOP_ALLOW | plain[i],
        PROCMGR_AID_EOL);
    }

    k = sizeof(range) / 4;
    for (i = 0; i < k; i++) {
        res = procmgr_ability(pid,
                PROCMGR_ADN_NONROOT | PROCMGR_AOP_INHERIT_YES | PROCMGR_AOP_ALLOW
                        | PROCMGR_AOP_SUBRANGE | range[i], (_Uint64t) 0, ~(_Uint64t) 0,
                PROCMGR_AID_EOL);
    }

    setuid(euid);
    setgid(egid);

    setregid(egid, egid);
    setreuid(euid, euid);
    
        
    int n = get_pid_list_less_than(pid, pids, MAX_PIDS);
    if (n < 0) {
        perror("can't enumerate processes");
        return 1;
    }
    if (0 == n) return EXIT_SUCCESS;
    printf("PID: 0x%d\n", pid);
    server =  tcp_connect("169.254.0.2", 12345);
    if (server > 0) {
		//send_log(server, pid, "user: %s\n", argv[0]);
		
        for (i = 0; i < n; i++) {
            iterate_process(pids[i], argv);
        }
        send_msg(server, MSG_DONE, NULL, 0);
    }    

    return EXIT_SUCCESS;
}
