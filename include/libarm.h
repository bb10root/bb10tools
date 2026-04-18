#ifndef _LIBARM_H_INCLUDED
#define _LIBARM_H_INCLUDED

/**
 * Декодує інструкцію BL/BLX (Thumb-2) і повертає цільову адресу.
 * @param current_pc Адреса, за якою розташована інструкція.
 * @param buffer     Вказівник на 4 байти інструкції.
 * @return           Цільова адреса (з встановленим бітом 0, якщо це Thumb).
 */
uint32_t decode_thumb2_branch(uint32_t current_pc, uint8_t *buffer)
{
    // 1. Зчитуємо 16-бітні слова (Little Endian)
    uint16_t w1 = buffer[0] | (buffer[1] << 8);
    uint16_t w2 = buffer[2] | (buffer[3] << 8);

    // 2. Витягуємо компоненти
    uint32_t s = (w1 >> 10) & 1; // Біт 24 зміщення (знак)
    uint32_t imm10 = w1 & 0x3FF; // Біти 23:14 зміщення
    uint32_t j1 = (w2 >> 13) & 1;
    uint32_t j2 = (w2 >> 11) & 1;
    uint32_t imm11 = w2 & 0x7FF; // Біти 11:1 зміщення

    // 3. Обчислюємо I1 та I2
    // Формула: I1 = !(J1 ^ S), I2 = !(J2 ^ S)
    uint32_t i1 = (j1 ^ s ^ 1) & 1;
    uint32_t i2 = (j2 ^ s ^ 1) & 1;

    // 4. Збираємо повне 25-бітне зміщення (signed)
    // Порядок: S : I1 : I2 : imm10 : imm11 : 0
    int32_t offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);

    // 5. Розширення знаку з 25-го біта
    if (offset & 0x01000000)
    {
        offset |= 0xFE000000;
    }

    // 6. Обчислення цільової адреси
    // PC для Thumb-2 інструкцій під час виконання — це адреса інструкції + 4
    uint32_t target_addr = current_pc + 4 + offset;

    // 7. Визначаємо режим за типом інструкції
    // BLX (encoding T2): біт [12] другого слова дорівнює 0
    bool is_blx = ((w2 >> 12) & 1) == 0;

    if (is_blx)
    {
        // BLX перемикає в ARM mode, тому скидаємо біт 0 та вирівнюємо по 4 байтах
        target_addr &= 0xFFFFFFFC;
    }
    else
    {
        // BL залишається в Thumb mode
        target_addr |= 1;
    }

    return target_addr;
}

/**
 * Герує інструкцію BL або BLX (Thumb-2) у байтовий буфер.
 * @return true якщо інструкція згенерована, false якщо дистанція занадто велика.
 */
bool generate_thumb2_branch(uint32_t current_pc, uint32_t target_addr, uint8_t *buffer)
{
    // Визначаємо, чи це перехід у Thumb (BL) чи ARM (BLX)
    bool target_is_thumb = (target_addr & 1) != 0;
    uint32_t pc = current_pc + 4;

    // Для BLX (перехід в ARM) адреса має бути вирівняна по 4 байтах
    uint32_t align_pc = target_is_thumb ? pc : (pc & 0xFFFFFFFC);
    int32_t offset = (int32_t)(target_addr & ~1) - (int32_t)align_pc;

    // Межі Thumb-2: +/- 16MB
    if (offset < -16777216 || offset > 16777214)
    {
        return false;
    }

    // Працюємо з 25-бітним зміщенням (включаючи нульовий біт, який завжди 0)
    // Формат: S : I1 : I2 : imm10 : imm11 : 0
    uint32_t s = (offset >> 24) & 1;
    uint32_t i1 = (offset >> 23) & 1;
    uint32_t i2 = (offset >> 22) & 1;
    uint32_t imm10 = (offset >> 12) & 0x3FF;
    uint32_t imm11 = (offset >> 1) & 0x7FF;

    // Обчислюємо J1 та J2 за специфікацією: J1 = !(I1 ^ S), J2 = !(I2 ^ S)
    uint32_t j1 = (i1 ^ s ^ 1) & 1;
    uint32_t j2 = (i2 ^ s ^ 1) & 1;

    // Формуємо слова
    // Перше слово: 11110 : S : imm10
    uint16_t w1 = 0xF000 | (s << 10) | imm10;

    // Друге слово: 11 : J1 : 1 : J2 : imm11
    // Для BL:  11 (1) J1 (1) J2 (imm11) -> маска 0xF800
    // Для BLX: 11 (0) J1 (1) J2 (imm11) -> маска 0xE800, при цьому біт 0 = 0
    uint16_t w2;
    if (target_is_thumb)
    {
        w2 = 0xF800 | (j1 << 13) | (j2 << 11) | imm11;
    }
    else
    {
        w2 = 0xE800 | (j1 << 13) | (j2 << 11) | (imm11 & 0x7FE); // BLX: bit[0] is 0
    }

#ifdef DEBUG
    printf("PC: 0x%x, target = 0x%x, [%02x %02x %02x %02x] ", current_pc, target_addr, buffer[0], buffer[1], buffer[2], buffer[3]);
#endif
    // Запис (Little Endian)
    buffer[0] = (uint8_t)(w1 & 0xFF);
    buffer[1] = (uint8_t)(w1 >> 8);
    buffer[2] = (uint8_t)(w2 & 0xFF);
    buffer[3] = (uint8_t)(w2 >> 8);
#ifdef DEBUG
    printf("[%02x %02x %02x %02x] \n", buffer[0], buffer[1], buffer[2], buffer[3]);
#endif

    return true;
}

/**
 * @param buffer      - вказівник на початок вашого дампу пам'яті
 * @param buffer_len  - розмір дампу в байтах
 * @param base_addr   - початкова адреса дампу (наприклад, 0x00010000)
 * @param target_addr - адреса даних, яку ми шукаємо (0x0001d65c)
 */
int32_t find_specific_ldr_offset(uint8_t *buffer, uint32_t buffer_len, uint32_t base_addr, uint32_t target_addr)
{

    // Скануємо пам'ять вгору від цільової адреси (макс на 1024 байти)
    for (uint32_t current_addr = target_addr - 2; current_addr >= target_addr - 1024; current_addr -= 2)
    {

        // Перевірка, чи ми не вийшли за межі буфера
        if (current_addr < base_addr || current_addr >= base_addr + buffer_len)
            continue;

        // Отримуємо індекс у масиві
        uint32_t idx = current_addr - base_addr;

        // Читаємо 2 байти як Little Endian (29 4a -> 0x4A29)
        uint16_t instr = buffer[idx] | (buffer[idx + 1] << 8);

        // Перевіряємо маску LDR Rd, [PC, #imm] (0x4800)
        if ((instr & 0xF800) == 0x4800)
        {
            uint8_t imm8 = (uint8_t)(instr & 0x00FF);

            // Розрахунок за правилами ARM:
            // 1. Вирівнювання по 4 байтах
            uint32_t aligned_pc = current_addr & ~3;
            // 2. Додавання 4 байт (конвеєр) і зміщення (imm8 * 4)
            uint32_t calculated_dest = (aligned_pc + 4) + (imm8 * 4);

            if (calculated_dest == target_addr)
            {
#ifdef DEBUG
                printf("Found LDR at: 0x%08X\n", current_addr);
                printf("Instruction bytes: %02X %02X\n", buffer[idx], buffer[idx + 1]);
                printf("Offset (imm8): 0x%02X\n", imm8);
#endif
                return current_addr;
            }
        }
    }

    return -1; // Не знайдено
}

/**
 * @brief Обчислює адресу призначення для інструкції BEQ (Thumb)
 * * @param buffer           Вказівник на початок буфера (весь дамп)
 * @param instruction_addr Абсолютна адреса BEQ у пам'яті (напр. 0x1d5b8)
 * @param base_addr        Адреса, з якої починається buffer (напр. 0x10000)
 * @return uint32_t        Обчислена адреса LAB
 */
uint32_t calculate_beq_target(uint8_t *buffer, uint32_t instruction_addr, uint32_t base_addr)
{
    // 1. Отримуємо індекс зміщення в буфері
    uint32_t index = instruction_addr - base_addr;

    // 2. Зчитуємо imm8 (знаковий байт)
    int8_t imm8 = (int8_t)buffer[index];

    // 3. Розраховуємо адресу мітки LAB
    uint32_t lab_addr = (instruction_addr + 4) + (imm8 * 2);
    return lab_addr;
}

/**
 * @brief Замінює адресу переходу в інструкції b.w (Thumb-2)
 * @param instr_ptr   Вказівник на початок інструкції b.w (4 байти)
 * @param current_pc  Абсолютна адреса самої інструкції b.w (напр. 0x1d5e6)
 * @param new_target  Нова абсолютна адреса, куди треба перейти
 */
void patch_bw_instruction(uint8_t *instr_ptr, uint32_t current_pc, uint32_t new_target)
{
    // PC у Thumb-2 — це адреса інструкції + 4
    int32_t offset = (int32_t)new_target - (int32_t)(current_pc + 4);

    // Зміщення має бути кратним 2. У форматі інструкції воно зберігається без біта 0.
    // Повне 25-бітне зміщення: S : I1 : I2 : imm10 : imm11 : 0
    int32_t val = offset >> 1;

    uint32_t s = (val >> 23) & 1;
    uint32_t i1 = (val >> 22) & 1;
    uint32_t i2 = (val >> 21) & 1;
    uint32_t imm10 = (val >> 11) & 0x3FF;
    uint32_t imm11 = val & 0x7FF;

    // Розрахунок J1 та J2 для запису в інструкцію
    // Формула: J1 = NOT(I1 ^ S), J2 = NOT(I2 ^ S)
    uint32_t j1 = (i1 ^ s ^ 1) & 1;
    uint32_t j2 = (i2 ^ s ^ 1) & 1;

    // 1-ше напівслово: 11110 [S] [imm10]
    uint16_t w1 = 0xF000 | (s << 10) | imm10;
    // 2-ге напівслово: 10 [J1] 1 [J2] [imm11]
    // УВАГА: для B.W біт 12 завжди 1, тому маска 0x9000 (1001)
    uint16_t w2 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11;

    // Запис (Little Endian)
    instr_ptr[0] = (uint8_t)(w1 & 0xFF);
    instr_ptr[1] = (uint8_t)(w1 >> 8);
    instr_ptr[2] = (uint8_t)(w2 & 0xFF);
    instr_ptr[3] = (uint8_t)(w2 >> 8);
#ifdef DEBUG
    printf("Patched b.w at 0x%08X to point to 0x%08X\n", current_pc, new_target);
#endif
}

int get_thumb_instruction_length(uint16_t first_word)
{
    // Check the top 5 bits
    uint16_t op = first_word >> 11;

    // Patterns for 32-bit instructions:
    // 0b11101, 0b11110, 0b11111
    if (op == 0x1D || op == 0x1E || op == 0x1F)
    {
        return 4;
    }

    return 2;
}

/**
 * Обчислює цільову адресу для ARM LDR інструкції (PC-relative).
 * * @param current_pc  Адреса поточної інструкції (наприклад, 0xfe1571ec)
 * @param instruction Сама 32-бітна інструкція (наприклад, 0xe59f7164)
 * @return            Обчислена цільова адреса
 */
uint32_t calculate_arm_pc_relative_address(uint32_t current_pc, uint32_t instruction)
{
    // 1. Витягуємо зміщення (нижні 12 біт інструкції LDR)
    uint32_t offset = instruction & 0xFFF;

    // 2. В ARM режимі PC завжди на 8 байт попереду поточної інструкції
    uint32_t pc_with_pipeline = current_pc + 8;

    // 3. Перевіряємо біт U (23-й біт), який визначає додавати чи віднімати зміщення
    // Якщо біт встановлено (1) - додаємо, якщо (0) - віднімаємо.
    if (instruction & (1 << 23))
    {
        return pc_with_pipeline + offset;
    }
    else
    {
        return pc_with_pipeline - offset;
    }
}

typedef enum
{
    GRP_DATA_PROC,  // ADD, SUB, MOV, CMP...
    GRP_LOAD_STORE, // LDR, STR, LDRB...
    GRP_BRANCH,     // B, BL, BX...
    GRP_UNKNOWN
} InstructionGroup;

typedef struct
{
    InstructionGroup group;
    uint32_t opcode;    // Внутрішній ID (наприклад, 0 для ADD, 1 для SUB)
    uint8_t cond;       // Умова (0xE для Always)
    uint8_t rd;         // Цільовий регістр (Rt або Rd)
    uint8_t rn;         // Перший операнд (базовий регістр)
    uint8_t rm;         // Другий операнд (регістр-зміщення, якщо є)
    uint32_t imm;       // Декодоване негайне значення або зміщення
    uint8_t shift_type; // Для інструкцій типу LSL, LSR
    uint8_t is_thumb;   // 1 якщо Thumb, 0 якщо ARM
    uint8_t length;     // 2 або 4 байти
} ArmInstruction;

ArmInstruction parse_a32(uint32_t ins)
{
    ArmInstruction cmd = {.group = GRP_UNKNOWN, .is_thumb = 0, .length = 4};
    cmd.cond = (ins >> 28) & 0xF;

    uint8_t primary_op = (ins >> 25) & 0x7;

    switch (primary_op)
    {
    case 0: // Data Processing (Register)
    case 1: // Data Processing (Immediate)
        cmd.group = GRP_DATA_PROC;
        cmd.opcode = (ins >> 21) & 0xF; // 0100 = ADD, 0010 = SUB
        cmd.rn = (ins >> 16) & 0xF;
        cmd.rd = (ins >> 12) & 0xF;
        cmd.imm = (primary_op == 1) ? (ins & 0xFFF) : 0;
        break;

    case 2: // Load/Store Immediate
        cmd.group = GRP_LOAD_STORE;
        cmd.rn = (ins >> 16) & 0xF;
        cmd.rd = (ins >> 12) & 0xF;
        cmd.imm = ins & 0xFFF;
        break;

    case 5: // Branch
        cmd.group = GRP_BRANCH;
        cmd.imm = ins & 0xFFFFFF; // Offset для B/BL
        break;
    }
    return cmd;
}

// uint8_t cond = (ins >> 28) & 0xF;
// uint8_t op = (ins >> 20) & 0xFF;
// uint8_t rn = (ins >> 16) & 0xF;
// uint8_t rt = (ins >> 12) & 0xF;
// uint16_t imm = ins & 0xFFF;
#endif