import os
import hashlib
import json
import argparse

DB_FILE = "signatures.json"

def get_page_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            header = f.read(0x1000)
            if header.startswith(b'\x7fELF'):
                return hashlib.sha256(header).hexdigest()
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Індексація еталонних ELF-файлів")
    parser.add_argument("-p", "--path", required=True, help="Шлях до папки з еталонами")
    args = parser.parse_args()

    hash_db = {}
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            hash_db = json.load(f)

    print(f"[*] Індексація: {args.path}")
    new_count = 0
    for root, _, files in os.walk(args.path):
        for file in files:
            full_path = os.path.join(root, file)
            h = get_page_hash(full_path)
            if h and h not in hash_db:
                hash_db[h] = file
                new_count += 1

    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(hash_db, f, indent=4)
    print(f"[+] Готово. Додано: {new_count}. Усього в базі: {len(hash_db)}")

if __name__ == "__main__":
    main()
