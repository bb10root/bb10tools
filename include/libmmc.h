#ifndef _LIBMMC_H_INCLUDED
#define _LIBMMC_H_INCLUDED

#define BLOCK_SIZE 512
#define NUM_BLOCKS(x) (((x) + (BLOCK_SIZE) - 1) / (BLOCK_SIZE))

/* For "devctl()" */
#include <devctl.h>
#include <hw/dcmd_sim_sdmmc.h>
#include <sys/dcmd_cam.h>
#include <sys/cam_device.h>
#include <mmc/sim_sdmmc.h>
#include <mmc_internal.h>
#include <mmc/ntocam.h>
#include <mmc/sim.h>
#include <mmc/mmc.h>
#include <mmc/mmc2.h>
#include <mmc_shared.h>

typedef struct
{
    uint32_t address;
    uint32_t old;
    uint32_t new;
} patch_t;

/**
 * Відправка сирої команди без даних
 */
int send_raw_cmd_no_data(int fd, uint32_t cmd_idx, uint32_t arg,
                         uint32_t flags, uint32_t timeout_ms, uint32_t *rsp)
{
    sdmmc_raw_cmd_t cmd;
    int ret;
    int devctl_status;

    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd_idx = cmd_idx;
    cmd.p.mmc.cmd_arg = arg;
    cmd.p.mmc.cmd_flags = flags;
    cmd.p.mmc.data_dir = SDMMC_RAW_DATA_NONE;
    cmd.p.mmc.blocksize = 0;
    cmd.p.mmc.blocks = 0;
    cmd.p.mmc.timeout_ms = timeout_ms;

    ret = devctl(fd, DCMD_SDMMC_ANY, &cmd, sizeof(cmd), &devctl_status);
    if (ret != EOK)
    {
        fprintf(stderr, "devctl system call failed: ret=%d %s (%d)\n", ret, strerror(errno), errno);
        return -1;
    }

    /* Перевіряємо статус, який повернув драйвер */
    if (devctl_status != EOK)
    {
        fprintf(stderr, "Command failed with status: %s (%d)\n",
                strerror(devctl_status), devctl_status);
        return -1;
    }

    /* Копіюємо відповідь */
    if (rsp != NULL)
    {
        memcpy(rsp, cmd.rsp, sizeof(cmd.rsp));
    }

    return 0;
}

/**
 * Відправка команди з читанням даних
 */
int send_raw_cmd_read(int fd, uint32_t cmd_idx, uint32_t arg,
                      uint32_t flags, uint32_t blocksize, uint32_t blocks,
                      void *buffer, size_t buf_len, uint32_t timeout_ms,
                      uint32_t *rsp)
{
    size_t total_size;
    uint8_t *payload;
    sdmmc_raw_cmd_t *cmd;
    int ret;
    int devctl_status;

    total_size = sizeof(sdmmc_raw_cmd_t) + blocksize * blocks;

    if (buf_len < blocksize * blocks)
    {
        fprintf(stderr, "Buffer too small: need %u, got %zu\n",
                blocksize * blocks, buf_len);
        return -1;
    }

    payload = malloc(total_size);
    if (payload == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }

    cmd = (sdmmc_raw_cmd_t *)payload;
    memset(cmd, 0, sizeof(*cmd));

    cmd->cmd_idx = cmd_idx;
    cmd->p.mmc.cmd_arg = arg;
    cmd->p.mmc.cmd_flags = flags;
    cmd->p.mmc.data_dir = SDMMC_RAW_DATA_READ;
    cmd->p.mmc.blocksize = blocksize;
    cmd->p.mmc.blocks = blocks;
    cmd->p.mmc.timeout_ms = timeout_ms;

    ret = devctl(fd, DCMD_SDMMC_ANY, payload, total_size, &devctl_status);
    if (ret != EOK)
    {
        fprintf(stderr, "devctl system call failed: ret=%d %s (%d)\n", ret, strerror(errno), errno);
        free(payload);
        return -1;
    }

    /* Перевіряємо статус, який повернув драйвер */
    if (devctl_status != EOK)
    {
        fprintf(stderr, "Read command failed with status: %s (%d)\n",
                strerror(devctl_status), devctl_status);
        free(payload);
        return -1;
    }

    /* Копіюємо дані та відповідь */
    memcpy(buffer, payload + sizeof(sdmmc_raw_cmd_t), blocksize * blocks);

    if (rsp != NULL)
    {
        memcpy(rsp, cmd->rsp, sizeof(cmd->rsp));
    }

    free(payload);
    return 0;
}

/**
 * Відправка команди з записом даних
 */
int send_raw_cmd_write(int fd, uint32_t cmd_idx, uint32_t arg,
                       uint32_t flags, uint32_t blocksize, uint32_t blocks,
                       const void *buffer, size_t buf_len, uint32_t timeout_ms,
                       uint32_t *rsp)
{
    size_t total_size;
    uint8_t *payload;
    sdmmc_raw_cmd_t *cmd;
    int ret;
    int devctl_status;

    if (buf_len < blocksize * blocks)
    {
        fprintf(stderr, "Buffer size mismatch: need %u, got %zu\n",
                blocksize * blocks, buf_len);
        return -1;
    }

    total_size = sizeof(sdmmc_raw_cmd_t) + blocksize * blocks;

    payload = malloc(total_size);
    if (payload == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }

    cmd = (sdmmc_raw_cmd_t *)payload;
    memset(cmd, 0, sizeof(*cmd));

    cmd->cmd_idx = cmd_idx;
    cmd->p.mmc.cmd_arg = arg;
    cmd->p.mmc.cmd_flags = flags;
    cmd->p.mmc.data_dir = SDMMC_RAW_DATA_WRITE;
    cmd->p.mmc.blocksize = blocksize;
    cmd->p.mmc.blocks = blocks;
    cmd->p.mmc.timeout_ms = timeout_ms;

    /* Копіюємо дані для запису */
    memcpy(payload + sizeof(sdmmc_raw_cmd_t), buffer, blocksize * blocks);

    ret = devctl(fd, DCMD_SDMMC_ANY, payload, total_size, &devctl_status);
    if (ret != EOK)
    {
        fprintf(stderr, "devctl system call failed: ret=%d %s (%d)\n", ret, strerror(errno), errno);
        free(payload);
        return -1;
    }

    /* Перевіряємо статус, який повернув драйвер */
    if (devctl_status != EOK)
    {
        fprintf(stderr, "Write command failed with status: %s (%d)\n",
                strerror(devctl_status), devctl_status);
        free(payload);
        return -1;
    }

    /* Копіюємо відповідь */
    if (rsp != NULL)
    {
        memcpy(rsp, cmd->rsp, sizeof(cmd->rsp));
    }

    free(payload);
    return 0;
}

static int send_cmd62(int fd, uint32_t arg)
{
    uint32_t rsp[4];
    return send_raw_cmd_no_data(fd, 62, arg, (SCF_WAIT_DRDY | SCF_DIR_IN | SCF_RSP_R1B | SCF_CTYPE_AC), 1000, rsp);
}

static int send_cmd60(int fd, uint32_t arg)
{
    uint32_t rsp[4];
    return send_raw_cmd_no_data(fd, 60, arg, (SCF_WAIT_DRDY | SCF_DIR_IN | SCF_RSP_R1B | SCF_CTYPE_AC), 1000, rsp);
}

int mmc_enter_read_ram(int fd)
{
    if (send_cmd62(fd, 0xefac62ec) < 0)
        return -1;
    return send_cmd62(fd, 0x10210002);
}

int mmc_enter_write_ram(int fd)
{
    if (send_cmd62(fd, 0xefac62ec) < 0)
        return -1;
    return send_cmd62(fd, 0x10210001);
}

int mmc_enter_read_dword(int fd)
{
    if (send_cmd62(fd, 0xefac62ec) < 0)
        return -1;
    return send_cmd62(fd, 0x10210003);
}

int mmc_enter_write_dword(int fd)
{
    if (send_cmd62(fd, 0xefac62ec) < 0)
        return -1;
    return send_cmd62(fd, 0x10210000);
}

int mmc_exit_cmd62(int fd)
{
    if (send_cmd62(fd, 0xefac62ec) < 0)
        return -1;
    return send_cmd62(fd, 0x00deccee);
}

int mmc_activate_cmd60(int fd)
{
    return send_cmd60(fd, 0xefac60fc);
}

int mmc_enter_jump(int fd)
{
    if (mmc_activate_cmd60(fd) < 0)
        return -1;
    return send_cmd60(fd, 0x10210010);
}

int mmc_enter_firmware_upgrade(int fd)
{
    if (mmc_activate_cmd60(fd) < 0)
        return -1;
    return send_cmd60(fd, 0xcbad1160);
}

int mmc_firmware_activate(int fd, unsigned type)
{
    if (mmc_activate_cmd60(fd) < 0)
        return -1;
    return send_cmd60(fd, 0xabcd1280 + type);
}

int mmc_start_timer(int fd)
{
    uint32_t rsp[4] = {0};
    if (mmc_activate_cmd60(fd) < 0)
        return -1;
    if (send_raw_cmd_no_data(fd, 60, 0xabcd1240, SCF_RSP_R1B, 1000, rsp) < 0)
        return -1;
    return (int)rsp[0];
}

int mmc_movi_erase(int fd, uint32_t a1, uint32_t a2)
{
    uint32_t rsp[4];
    /* CMD35 - Address to read */
    if (send_raw_cmd_no_data(fd, 35, a1, SCF_RSP_R1, 1000, rsp) < 0)
        return -1;

    /* CMD36 - Length to read */
    if (send_raw_cmd_no_data(fd, 36, a2, SCF_RSP_R1, 1000, rsp) < 0)
        return -1;

    /* CMD38 - Perform read RAM operation */
    if (send_raw_cmd_no_data(fd, 38, 0, SCF_RSP_R1B, 1000, rsp) < 0)
        return -1;
    return 0;
}

int mmc_read_ram(int fd, uint32_t addr, uint32_t size, uint8_t *out_buf)
{
    uint32_t rsp[4];
    uint32_t num_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint32_t i = 0; i < num_blocks; i++)
    {
        /* CMD35 - Address to read */
        if (send_raw_cmd_no_data(fd, 35, addr + i * BLOCK_SIZE, SCF_RSP_R1, 1000, rsp) < 0)
            return -1;

        /* CMD36 - Length to read */
        if (send_raw_cmd_no_data(fd, 36, BLOCK_SIZE, SCF_RSP_R1, 1000, rsp) < 0)
            return -1;

        /* CMD38 - Perform read RAM operation */
        if (send_raw_cmd_no_data(fd, 38, 0, SCF_RSP_R1B, 1000, rsp) < 0)
            return -1;

        /* CMD17 - Read data */
        if (send_raw_cmd_read(fd, 17, 0, SCF_RSP_R1 | SCF_CTYPE_ADTC,
                              BLOCK_SIZE, 1,
                              out_buf + i * BLOCK_SIZE, BLOCK_SIZE,
                              3000, rsp) < 0)
            return -1;
    }
    return 0;
}

/**
 * CMD17 (READ_SINGLE_BLOCK) - читання одного блоку
 */
int example_read_block(int fd, uint32_t block_addr)
{
    uint8_t buffer[512];
    uint32_t rsp[4];
    int ret;
    int i;

    printf("Reading block %u...\n", block_addr);

    ret = send_raw_cmd_read(fd, 17, block_addr, SCF_RSP_R1,
                            512, 1, buffer, sizeof(buffer), 3000, rsp);
    if (ret == 0)
    {
        printf("Success! Response: 0x%08X\n", rsp[0]);
        printf("First 64 bytes:\n");
        for (i = 0; i < 64; i++)
        {
            printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
    }
    else
    {
        printf("Read block failed\n");
    }

    return ret;
}

/**
 * CMD13 (SEND_STATUS) - отримання статусу картки
 */
int example_cmd13(int fd, uint32_t rca)
{
    uint32_t rsp[4];
    int ret;

    printf("Sending CMD13 (SEND_STATUS) for RCA=0x%04X...\n", rca);

    ret = send_raw_cmd_no_data(fd, 13, rca << 16, SCF_RSP_R1, 1000, rsp);
    if (ret == 0)
    {
        printf("Card Status: 0x%08X\n", rsp[0]);
        printf("  Ready: %s\n", (rsp[0] & (1 << 8)) ? "YES" : "NO");
        printf("  State: %u\n", (rsp[0] >> 9) & 0xF);
    }

    return ret;
}

typedef struct _mmc_ext_csd
{
    uint32_t hs_max_dtr;
    uint32_t sectors;
    uint8_t erase_grp_def;
    uint8_t hc_erase_group_size;
    uint8_t hc_wp_grp_size;
    uint8_t user_wp;
} mmc_ext_csd_t;

typedef struct _mmc_csd_t
{
    uint8_t csd_structure; // CSD structure
#define CSD_VERSION_10 0   /* 1.0 - 1.2 */
#define CSD_VERSION_11 1   /* 1.4 -  */
#define CSD_VERSION_12 2   /* 2.0 - 2.2 */
#define CSD_VERSION_13 3   /* 3.1 - 3.2 - 3.31 */
#define CSD_VERSION_14 4   /* 4.0 - 4.1 */
    uint8_t mmc_prot;
    uint8_t taac;
    uint8_t nsac;
    uint8_t tran_speed;
    uint16_t ccc;
    uint8_t read_bl_len;
    uint8_t read_bl_partial;
    uint8_t write_blk_misalign;
    uint8_t read_blk_misalign;
    uint8_t dsr_imp;
    uint16_t c_size;
    uint8_t vdd_r_curr_min;
    uint8_t vdd_r_curr_max;
    uint8_t vdd_w_curr_min;
    uint8_t vdd_w_curr_max;
    uint8_t c_size_mult;
    union
    {
        struct
        { /* MMC system specification version 3.1 */
            uint8_t erase_grp_size;
            uint8_t erase_grp_mult;
        } mmc_v31;
        struct
        { /* MMC system specification version 2.2 */
            uint8_t sector_size;
            uint8_t erase_grp_size;
        } mmc_v22;
    } erase;
    mmc_ext_csd_t ext_csd;
    uint8_t wp_grp_size;
    uint8_t wp_grp_enable;
    uint8_t r2w_factor;
    uint8_t write_bl_len;
    uint8_t write_bl_partial;
    //  uint8_t     file_format_grp;
    uint8_t copy;
    uint8_t perm_write_protect;
    uint8_t tmp_write_protect;
    uint8_t ecc;
} mmc_csd_t;

/*
 * sdcc_base=0x12400000, size=0x800 (mapped at 0x2803B000)
 *  dml_base=0x12400800, size=0x100 (mapped at 0x2800E800)
 *  bam_base=0x12402000, size=0x4000 (mapped at 0x28007000)
 *
 */

char *vendorFromID(int id)
{

    switch (id)
    {
    case MID_MMC_SANDISK:
    case MID_MMC_SANDISK_2:
        return "SANDISK";
    case MID_MMC_TOSHIBA:
        return "TOSHIBA";
    case MID_MMC_MICRON:
        return "MICRON";
    case MID_MMC_SAMSUNG:
        return "SAMSUNG";
    case MID_MMC_HYNIX:
        return "HYNIX";
    case MID_MMC_NUMONYX:
        return "NUMONYX";
    default:
        return "UNKNOWN";
    }
}

void mem_display(const void *address)
{
    const unsigned char *p = address;
    size_t i;
    for (i = 0; i < 4; i++)
    {
        printf("%02hhx", p[4 * i + 3]);
        printf("%02hhx", p[4 * i + 2]);
        printf("%02hhx", p[4 * i + 1]);
        printf("%02hhx", p[4 * i + 0]);
    }
}

static void print_writeprotect_boot_status(_Uint8t *ext_csd)
{
    _Uint8t reg;
    _Uint8t ext_csd_rev = ext_csd[EXT_CSD_REV];

    /* A43: reserved [174:0] */
    if (ext_csd_rev >= 5)
    {
        printf("Boot write protection status registers"
               " [BOOT_WP_STATUS]: 0x%02x\n",
               ext_csd[174]);

        reg = ext_csd[EXT_CSD_BOOT_WP];
        printf("Boot Area Write protection [BOOT_WP]: 0x%02x\n", reg);
        printf(" Power ro locking: ");
        if (reg & EXT_CSD_BOOT_WP_B_PWR_WP_DIS)
            printf("not possible\n");
        else
            printf("possible\n");

        printf(" Permanent ro locking: ");
        if (reg & EXT_CSD_BOOT_WP_B_PERM_WP_DIS)
            printf("not possible\n");
        else
            printf("possible\n");

        reg = ext_csd[EXT_CSD_BOOT_WP_STATUS];
        printf(" partition 0 ro lock status: ");
        if (reg & EXT_CSD_BOOT_WP_S_AREA_0_PERM)
            printf("locked permanently\n");
        else if (reg & EXT_CSD_BOOT_WP_S_AREA_0_PWR)
            printf("locked until next power on\n");
        else
            printf("not locked\n");
        printf(" partition 1 ro lock status: ");
        if (reg & EXT_CSD_BOOT_WP_S_AREA_1_PERM)
            printf("locked permanently\n");
        else if (reg & EXT_CSD_BOOT_WP_S_AREA_1_PWR)
            printf("locked until next power on\n");
        else
            printf("not locked\n");
    }
}

static void mmc_disp_mmc_csd(mmc_csd_t *csd)
{
    printf("MMC CSD info:\n");
    printf(" CSD_STRUCTURE      : %x\n", csd->csd_structure);
    printf(" MMC_PROT           : %x\n", csd->mmc_prot);
    printf(" TAAC               : %x\n", csd->taac);
    printf(" NSAC               : %x\n", csd->nsac);
    printf(" TRAN_SPEED         : %x\n", csd->tran_speed);
    printf(" CCC                : %x\n", csd->ccc);
    printf(" READ_BL_LEN        : %x\n", csd->read_bl_len);
    printf(" READ_BL_PARTIAL    : %x\n", csd->read_bl_partial);
    printf(" WRITE_BLK_MISALIGN : %x\n", csd->write_blk_misalign);
    printf(" READ_BLK_MISALIGN  : %x\n", csd->read_blk_misalign);
    printf(" DSR_IMP            : %x\n", csd->dsr_imp);
    if (csd->csd_structure <= CSD_VERSION_11)
    {
        printf(" SECTOR_SIZE        : %x\n", csd->erase.mmc_v22.sector_size);
        printf(" ERASE_GRP_SIZE     : %x\n", csd->erase.mmc_v22.erase_grp_size);
    }
    else
    {
        printf(" ERASE_GRP_SIZE     : %x\n", csd->erase.mmc_v31.erase_grp_size);
        printf(" ERASE_GRP_MULT     : %x\n", csd->erase.mmc_v31.erase_grp_mult);
    }
    printf(" WP_GRP_SIZE        : %x\n", csd->wp_grp_size);
    printf(" R2W_FACTOR         : %x\n", csd->r2w_factor);
    printf(" WRITE_BL_LEN       : %x\n", csd->write_bl_len);
    printf(" WRITE_BL_PARTIAL   : %x\n", csd->write_bl_partial);
    printf(" COPY               : %x\n", csd->copy);
    printf(" PERM_WRITE_PROTECT : %x\n", csd->perm_write_protect);
    printf(" TMP_WRITE_PROTECT  : %x\n", csd->tmp_write_protect);
    printf(" ECC                : %x\n", csd->ecc);
}

void mmc_parse_mmc_csd(uint32_t *resp)
{
    uint32_t csize, csizem, bsize;
    mmc_csd_t *csd;
    csd = malloc(sizeof(mmc_csd_t));
    csd->csd_structure = resp[3] >> 30;
    csd->mmc_prot = (resp[3] >> 26) & 0x0F;
    csd->taac = resp[3] >> 16;
    csd->nsac = resp[3] >> 8;
    csd->tran_speed = resp[3];
    csd->ccc = resp[2] >> 20;
    csd->read_bl_len = (resp[2] >> 16) & 0x0F;
    csd->read_bl_partial = (resp[2] >> 15) & 1;
    csd->write_blk_misalign = (resp[2] >> 14) & 1;
    csd->read_blk_misalign = (resp[2] >> 13) & 1;
    csd->dsr_imp = (resp[2] >> 12) & 1;
    csd->c_size = ((resp[2] & 0x3FF) << 2) | (resp[1] >> 30);
    csd->vdd_r_curr_min = (resp[1] >> 27) & 0x07;
    csd->vdd_r_curr_max = (resp[1] >> 24) & 0x07;
    csd->vdd_w_curr_min = (resp[1] >> 21) & 0x07;
    csd->vdd_w_curr_max = (resp[1] >> 18) & 0x07;
    csd->c_size_mult = (resp[1] >> 15) & 0x07;

    if (csd->csd_structure <= CSD_VERSION_11)
    {
        csd->erase.mmc_v22.sector_size = (resp[1] >> 10) & 0x1F;
        csd->erase.mmc_v22.erase_grp_size = (resp[1] >> 5) & 0x1F;
    }
    else
    {
        csd->erase.mmc_v31.erase_grp_size = (resp[1] >> 10) & 0x1F;
        csd->erase.mmc_v31.erase_grp_mult = (resp[1] >> 5) & 0x1F;
    }
    csd->wp_grp_size = (resp[1] >> 0) & 0x1F;
    csd->wp_grp_enable = (resp[0] >> 31);
    csd->r2w_factor = (resp[0] >> 26) & 0x07;
    csd->write_bl_len = (resp[0] >> 22) & 0x0F;
    csd->write_bl_partial = (resp[0] >> 21) & 1;
    csd->copy = (resp[0] >> 14) & 1;
    csd->perm_write_protect = (resp[0] >> 13) & 1;
    csd->tmp_write_protect = (resp[0] >> 12) & 1;
    csd->ecc = (resp[0] >> 8) & 3;
    /*
     *     if (csd->perm_write_protect || csd->tmp_write_protect) {
     *     part->pflags |= MMC_PFLAG_WP;
}
*/
    bsize = 1 << csd->read_bl_len;
    csize = csd->c_size + 1;
    csizem = 1 << (csd->c_size_mult + 2);
    /*
     *     // force to 512 byte block
     *     if (bsize > MMC_DFLT_BLKSIZE && (bsize % MMC_DFLT_BLKSIZE) == 0) {
     *     uint32_t ts = bsize / MMC_DFLT_BLKSIZE;
     *     csize = csize * ts;
     *     bsize = bsize / ts;
}

ext->mmc_blksize    = bsize;
part->ptype         = MMC_PTYPE_USER;
part->slba          = 0;
part->nlba          = csize * csizem;
part->elba          = part->nlba - 1;
*/

    mmc_disp_mmc_csd(csd);
}

int mmc_read_ram_to_file(int fd, uint32_t addr, uint32_t size, const char *filename)
{
    uint32_t rsp[4];
    uint32_t num_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t block_buf[BLOCK_SIZE];
    FILE *f;
    int ret = 0;

    f = fopen(filename, "wb");
    if (!f)
    {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    if (mmc_enter_read_ram(fd) < 0)
    {
        fprintf(stderr, "Failed to enter read RAM mode\n");
        ret = -1;
        goto out;
    }

    for (uint32_t i = 0; i < num_blocks; i++)
    {
        uint32_t cur_addr = addr + i * BLOCK_SIZE;

        if (i % 16 == 0)
            printf("\rReading 0x%08X / 0x%08X ...", cur_addr, addr + size);
        fflush(stdout);

        /* Діапазон 0x20000-0x40000 — писати FF без читання з чипа */
        if (cur_addr >= 0x20000 && cur_addr < 0x40000)
        {
            memset(block_buf, 0xFF, BLOCK_SIZE);
            if (fwrite(block_buf, 1, BLOCK_SIZE, f) != BLOCK_SIZE)
            {
                fprintf(stderr, "\nFile write failed at block %u\n", i);
                ret = -1;
                goto exit_mode;
            }
            continue;
        }

        if (send_raw_cmd_no_data(fd, 35, cur_addr, SCF_RSP_R1, 1000, rsp) < 0 ||
            send_raw_cmd_no_data(fd, 36, BLOCK_SIZE, SCF_RSP_R1, 1000, rsp) < 0 ||
            send_raw_cmd_no_data(fd, 38, 0, SCF_RSP_R1B, 1000, rsp) < 0)
        {
            fprintf(stderr, "\nFailed at block %u (addr 0x%08X)\n", i, cur_addr);
            ret = -1;
            goto exit_mode;
        }

        if (send_raw_cmd_read(fd, 17, 0, SCF_RSP_R1,
                              BLOCK_SIZE, 1,
                              block_buf, BLOCK_SIZE,
                              3000, rsp) < 0)
        {
            fprintf(stderr, "\nRead failed at block %u (addr 0x%08X)\n", i, cur_addr);
            ret = -1;
            goto exit_mode;
        }

        if (fwrite(block_buf, 1, BLOCK_SIZE, f) != BLOCK_SIZE)
        {
            fprintf(stderr, "\nFile write failed at block %u\n", i);
            ret = -1;
            goto exit_mode;
        }
    }

    printf("\nDone. Written %u bytes to %s\n", num_blocks * BLOCK_SIZE, filename);

exit_mode:
    mmc_exit_cmd62(fd);

out:
    fclose(f);
    return ret;
}

int patchRW(int fd, patch_t *patches, int count)
{
    uint32_t rsp[4];

    uint32_t block_buf[512 / 4];
    int i;
    int ret = 0;
    printf("Open RAM for read\n");
    /* --- Перевірка поточних значень --- */
    mmc_enter_read_ram(fd);
    delay(10);
    printf("Check old\n");

    for (i = 0; i < count; i++)
    {
        if (mmc_movi_erase(fd, patches[i].address, 4))
        {
            fprintf(stderr, "\nmovi_erase failed at %u (addr 0x%08X)\n",
                    i, patches[i].address);
            ret = -1;
            goto exit_mode;
        }

        if (send_raw_cmd_read(fd, 17, 0, SCF_RSP_R1,
                              512, 1, block_buf, 512,
                              3000, rsp) < 0)
        {
            fprintf(stderr, "\nRead failed at %u (addr 0x%08X)\n",
                    i, patches[i].address);
            ret = -1;
            goto exit_mode;
        }

        if (block_buf[0] == patches[i].new)
            fprintf(stderr, "\nAlready patched at 0x%08X\n", patches[i].address);
        else if (block_buf[0] != patches[i].old)
            fprintf(stderr, "\nWrong value 0x%08X at 0x%08X, should be 0x%08X\n",
                    block_buf[0], patches[i].address, patches[i].old);
    }

    mmc_exit_cmd62(fd);
    delay(100);
    /* --- Запис нових значень --- */
    printf("Open RAM for write\n");
    mmc_enter_write_dword(fd);
    printf("Write patch\n");

    for (i = 0; i < count; i++)
        if (mmc_movi_erase(fd, patches[i].address, patches[i].new))
        {
            ret = -1;
            goto exit_mode;
        }

    mmc_exit_cmd62(fd);
    delay(100);

    printf("Open RAM for read\n");
    /* --- Верифікація після запису --- */
    mmc_enter_read_ram(fd);
    printf("Verify patch\n");

    for (i = 0; i < count; i++)
    {
        mmc_movi_erase(fd, patches[i].address, 4);

        if (send_raw_cmd_read(fd, 17, 0, SCF_RSP_R1,
                              512, 1, block_buf, 512,
                              3000, rsp) < 0)
        {
            fprintf(stderr, "\nRead failed at %u (addr 0x%08X)\n",
                    i, patches[i].address);
            ret = -1;
            goto exit_mode;
        }

        if (block_buf[0] == patches[i].old)
            fprintf(stderr, "\nCan't patch at 0x%08X\n", patches[i].address);
        else if (block_buf[0] != patches[i].new)
            fprintf(stderr, "\nWrong value 0x%08X at 0x%08X, should be 0x%08X\n",
                    block_buf[0], patches[i].address, patches[i].new);
    }

exit_mode:
    mmc_exit_cmd62(fd);
    return ret;
}

/**
 * Структура для представлення значущих байтів CID
 * Згідно з аналізом, контролер використовує байти за зміщенням
 * 0x102 (258 у десятковій) та 0xC8 (200 у десятковій) у внутрішній RAM.
 */
typedef struct
{
    uint8_t byte_102; // Значення з CID зміщення 0x102
    uint8_t byte_C8;  // Значення з CID зміщення 0xC8
} EMMC_Auth_Context;

/**
 * Функція розрахунку пари ключів для CMD62
 * Базується на логіці:
 * key1 = (byte_102 << 8) | (byte_C8 << 9) + (byte_102 << 9) ...
 * Фактично це змішування байтів ідентифікатора.
 */
void calculate_vendor_keys(EMMC_Auth_Context ctx, uint16_t *key1, uint16_t *key2)
{
    uint32_t temp_r12, temp_r3, temp_r8;

    // 1. Беремо байт 0x102 і зсуваємо вліво на 8 біт (r12)
    temp_r12 = (uint32_t)ctx.byte_102 << 8;

    // 2. Беремо байт 0xC8 і зсуваємо вліво на 9 біт (r3)
    temp_r3 = (uint32_t)ctx.byte_C8 << 9;

    // 3. Формуємо комбіноване значення (r8)
    // r8 = r3 + (r12 << 1)
    // Це еквівалентно: (byte_C8 << 9) + (byte_102 << 9)
    temp_r8 = temp_r3 + (temp_r12 << 1);

    // 4. Виділяємо фінальні ключі
    // В асемблері байти ключа записуються прямо в структуру
    // для подальшого використання у Vendor_62_Core.
    *key1 = (uint16_t)(temp_r8 & 0xFFFF);
    *key2 = (uint16_t)((temp_r8 >> 16) & 0xFFFF);
}

int main2()
{
    // ПРИКЛАД: Ці значення потрібно вичитати з вашого чипа через CMD10
    EMMC_Auth_Context my_cid;
    my_cid.byte_102 = 0x4A; // Наприклад, ревізія (ASCII 'J')
    my_cid.byte_C8 = 0x80;  // Наприклад, параметр ємності

    uint16_t k1, k2;
    calculate_vendor_keys(my_cid, &k1, &k2);

    printf("--- eMMC Vendor Auth Keygen ---\n");
    printf("Input CID bytes: 0x102=[0x%02X], 0xC8=[0x%02X]\n", my_cid.byte_102, my_cid.byte_C8);
    printf("Generated Key 1 (CMD62 Arg 1): 0x%04X\n", k1);
    printf("Generated Key 2 (CMD62 Arg 2): 0x%04X\n", k2);

    return 0;
}

#endif