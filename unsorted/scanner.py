import os
import hashlib
import json
import lief
import argparse
from datetime import datetime

DB_FILE = "signatures.json"
EXTRACT_DIR = "extracted_elfs"

def get_elf_info_lief(raw_data):
    try:
        binary = lief.ELF.parse(list(raw_data))
        if binary:
            last_offset = 0
            for segment in binary.segments:
                end_offset = segment.file_offset + segment.physical_size
                if end_offset > last_offset:
                    last_offset = end_offset
            return max(last_offset, 0x1000), str(binary.header.machine_type)
    except Exception:
        pass
    return 1024 * 1024, "Unknown"

def main():
    parser = argparse.ArgumentParser(description="Пошук та вилучення ELF (ARMv7 QNX) за допомогою LIEF")
    parser.add_argument("-d", "--dump", required=True, help="Шлях до файлу дампу")
    parser.add_argument("-b", "--base", required=True, help="Базова адреса в hex (напр. 0x0)")
    args = parser.parse_args()

    if not os.path.exists(DB_FILE):
        print(f"[-] Помилка: База {DB_FILE} не знайдена. Запустіть indexer.py спочатку.")
        return

    try:
        base_addr = int(args.base, 16)
    except ValueError:
        print("[-] Помилка: Базова адреса має бути в HEX форматі (напр. 0x1000)")
        return

    with open(DB_FILE, "r", encoding="utf-8") as f:
        known_hashes = json.load(f)

    if not os.path.exists(EXTRACT_DIR):
        os.makedirs(EXTRACT_DIR)

    log_name = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_size = os.path.getsize(args.dump)

    with open(args.dump, "rb") as f_dump, open(log_name, "w", encoding="utf-8") as log:
        print(f"[*] Старт аналізу: {args.dump} | База: 0x{base_addr:X}")

        for offset in range(0, file_size, 0x1000):
            f_dump.seek(offset)
            if f_dump.read(4) == b'\x7fELF':
                f_dump.seek(offset)
                header_sample = f_dump.read(0x10000)
                h = hashlib.sha256(header_sample[:0x1000]).hexdigest()

                identity = known_hashes.get(h)
                abs_addr = base_addr + offset
                real_size, arch = get_elf_info_lief(header_sample)

                if identity:
                    res = f"[KNOWN] 0x{abs_addr:X} | {identity} ({arch})"
                else:
                    ext_filename = f"qnx_0x{abs_addr:X}.elf"
                    f_dump.seek(offset)
                    with open(os.path.join(EXTRACT_DIR, ext_filename), "wb") as ef:
                        ef.write(f_dump.read(real_size))
                    res = f"[EXTRACTED] 0x{abs_addr:X} | Size: {real_size} | Arch: {arch}"

                print(f"[+] {res}")
                log.write(res + "\n")

    print(f"\n[!] Аналіз завершено. Лог: {log_name}")

if __name__ == "__main__":
    main()
