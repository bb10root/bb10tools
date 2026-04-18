import re
import argparse
from pathlib import Path

MAX_SIG_LEN = 0

def parse_hex_string(hex_str):
    """Перетворює рядок hex-байтів у список чисел (int) або None для ??."""
    parts = hex_str.replace('"', "").strip().split()
    result = []
    for p in parts:
        if p == "??":
            result.append(None)
        else:
            result.append(int(p, 16))
    return result


def create_static_sig(name, hex_lines):
    global MAX_SIG_LEN
    cleaned_hex = [parse_hex_string(line) for line in hex_lines if line.strip()]
    if not cleaned_hex:
        return None

    # Початкова довжина за найкоротшим варіантом
    length = min(len(h) for h in cleaned_hex)

    pattern_bytes = []
    mask_bytes = []

    for i in range(length):
        current_bytes = set(h[i] for h in cleaned_hex)

        # Якщо всі байти однакові і це не ??
        if len(current_bytes) == 1 and list(current_bytes)[0] is not None:
            pattern_bytes.append(f"0x{list(current_bytes)[0]:02X}")
            mask_bytes.append(1)
        else:
            pattern_bytes.append("0x00")
            mask_bytes.append(0)

    # --- НОВИЙ БЛОК: Відкидання розбіжностей з кінця ---
    # Поки останній байт у масці 0 (тобто був ??), видаляємо його
    while length > 0 and mask_bytes[length - 1] == 0:
        pattern_bytes.pop()
        mask_bytes.pop()
        length -= 1
    # --------------------------------------------------

    if length == 0:
        return None  # Сигнатура повністю розійшлася
    if length > MAX_SIG_LEN:
        MAX_SIG_LEN = length

    p_str = ", ".join(pattern_bytes)
    m_str = ", ".join([str(m) for m in mask_bytes])

    return f"""    {{
        .name = "{name}",
        .pattern = {{{p_str}}},
        .mask = {{{m_str}}},
        .len = {length},
        .found_offset = 0,
        .found = 0
    }}"""


def generate_header(input_path, output_path):
    with open(input_path, "r") as f:
        content = f.read()

    blocks = re.findall(r'(\w+)\s+((?:\s*"[a-fA-F0-9\s?]+")*)', content)

    sig_definitions = []
    for name, hex_block in blocks:
        hex_lines = re.findall(r'"([^"]+)"', hex_block)
        res = create_static_sig(name, hex_lines)
        if res:
            sig_definitions.append(res)

    header_content = f"""#ifndef SIGNATURES_H
#define SIGNATURES_H
#include <stddef.h>

#define MAX_SIG_LEN {MAX_SIG_LEN}

typedef struct {{
    const char* name;
    unsigned char pattern[MAX_SIG_LEN];
    unsigned char mask[MAX_SIG_LEN];
    size_t len;
    size_t found_offset;
    int found;
}} Signature;

static Signature db[] = {{
{",\n".join(sig_definitions)}
}};

#define SIG_COUNT (sizeof(db) / sizeof(Signature))

#endif // SIGNATURES_H
"""
    with open(output_path, "w") as f:
        f.write(header_content)
    print(f"Done! Created {output_path} with {len(sig_definitions)} signatures.")

def existing_file(path):
    p = Path(path)
    if not p.exists():
        raise argparse.ArgumentTypeError(f"File not found: {path}")
    return p

if __name__ == "__main__":
#     # Приклад вхідних даних у файлі signatures.txt
#     with open("signatures.txt", "w") as f:
#         f.write(
#             """
# sdio_free_cmd
#    "70 b5 0a 4b 0a 4a 7b 44 9d 58 04 46 05 f1 88 06 30 46 fc f7 f4 ea 00 23 23 60 ab 6a 30 46 63 60 1c 60 ac 62 bd e8 70 40 fc f7 5e ba"
#    "70 b5 0a 4b 0a 4a 7b 44 9d 58 04 46 05 f1 88 06 30 46 fc f7 c0 e9 00 23 23 60 ab 6a 30 46 63 60 1c 60 ac 62 bd e8 70 40 fc f7 2a b9"
#         """
#         )

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",  type=existing_file, required=True)
    parser.add_argument("-o", "--output", type=Path, default=Path("signatures.h"))
    args = parser.parse_args()
    generate_header(args.input, args.output)
