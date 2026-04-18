#ifndef _SHARED_H_INCLUDED
#define _SHARED_H_INCLUDED

/* Структура для передачі параметрів команди */
#define SDMMC_RAW_DATA_NONE 0
#define SDMMC_RAW_DATA_READ 1
#define SDMMC_RAW_DATA_WRITE 2

typedef struct _sdmmc_raw_cmd
{
    uint32_t cmd_idx; /* CMD index */
    union
    {
        struct
        {

            uint32_t cmd_arg;    /* argument */
            uint32_t cmd_flags;  /* SCF_CTYPE_* | SCF_RSP_* | optional extras */
            uint32_t data_dir;   /* NONE/READ/WRITE */
            uint32_t blocksize;  /* bytes */
            uint32_t blocks;     /* count */
            uint32_t timeout_ms; /* 0 = default */
        } mmc;
        struct
        {
            uint32_t param1;
            uint32_t param2;
            uint32_t param3;
            uint32_t param4;
            void *user_ptr; /* Якщо потрібно передати вказівник */
        } func;
    } p;

    uint32_t rsp[4]; /* output */
} sdmmc_raw_cmd_t;

#define DCMD_SDMMC_ANY __DIOTF(_DCMD_CAM, _SIM_MMCSD + 1, struct _sdmmc_raw_cmd)

/* Маска для визначення внутрішніх функцій драйвера */
#define SDMMC_INTERNAL_FUNC_MASK 0x80000000
#define GET_INTERNAL_CMD(idx) ((idx) & ~SDMMC_INTERNAL_FUNC_MASK)

/* Ваші кастомні команди */
#define FUNC_SDIO_SYNCHRONIZE (0x01)
#define FUNC_SDIO_SET_PARTITION (0x02)
#define FUNC_MMC_INIT_DEVICE (0x03)

#endif