#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import os
import sys


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def print_region(path1, path2, path3, start, length, show_hash):
    print(f"OFFSET 0x{start:08X}  LEN 0x{length:X} ({length} bytes)")

    if show_hash:
        with open(path1, "rb") as f1, open(path3, "rb") as f3:
            f1.seek(start)
            f3.seek(start)
            d1 = f1.read(length)
            d3 = f3.read(length)

        print(f"  file1/file2 sha256: {sha256_bytes(d1)}")
        print(f"  file3        sha256: {sha256_bytes(d3)}")


def compare_three_files(path1, path2, path3, min_size, chunk_size, show_hash, merge_gap):
    size1 = os.path.getsize(path1)
    size2 = os.path.getsize(path2)
    size3 = os.path.getsize(path3)

    if size1 != size2 or size1 != size3:
        print("[!] Warning: файли мають різні розміри:")
        print(f"    file1: {size1}")
        print(f"    file2: {size2}")
        print(f"    file3: {size3}")
        print("[!] Порівняння буде в межах min(size).")

    total_size = min(size1, size2, size3)

    f1 = open(path1, "rb")
    f2 = open(path2, "rb")
    f3 = open(path3, "rb")

    # Поточна "сира" область (без злиття)
    in_region = False
    region_start = 0
    region_len = 0

    # Остання збережена область (для merge)
    last_start = None
    last_len = None

    def flush_last():
        nonlocal last_start, last_len
        if last_start is None:
            return
        if last_len >= min_size:
            print_region(path1, path2, path3, last_start, last_len, show_hash)
        last_start = None
        last_len = None

    def push_region(start, length):
        """
        Додає нову область з урахуванням merge_gap.
        """
        nonlocal last_start, last_len

        if last_start is None:
            last_start = start
            last_len = length
            return

        last_end = last_start + last_len
        gap = start - last_end

        # якщо область починається ДО кінця останньої (теоретично не має бути)
        if gap < 0:
            # просто розширимо останню
            new_end = max(last_end, start + length)
            last_len = new_end - last_start
            return

        # якщо розрив маленький => зливаємо
        if gap <= merge_gap:
            new_end = start + length
            last_len = new_end - last_start
            return

        # інакше — друкуємо попередню і починаємо нову
        flush_last()
        last_start = start
        last_len = length

    try:
        offset = 0

        while offset < total_size:
            to_read = min(chunk_size, total_size - offset)

            b1 = f1.read(to_read)
            b2 = f2.read(to_read)
            b3 = f3.read(to_read)

            if len(b1) != to_read or len(b2) != to_read or len(b3) != to_read:
                break

            for i in range(to_read):
                same12 = (b1[i] == b2[i])
                diff3 = (b1[i] != b3[i])

                if same12 and diff3:
                    if not in_region:
                        in_region = True
                        region_start = offset + i
                        region_len = 1
                    else:
                        region_len += 1
                else:
                    if in_region:
                        push_region(region_start, region_len)
                        in_region = False
                        region_len = 0

            offset += to_read

        # якщо кінець файлу попав на область
        if in_region:
            push_region(region_start, region_len)

        # друкуємо останню накопичену область
        flush_last()

    finally:
        f1.close()
        f2.close()
        f3.close()


def main():
    ap = argparse.ArgumentParser(
        description="Find ranges where file1==file2 but file3 differs, with optional merge of close regions."
    )
    ap.add_argument("file1")
    ap.add_argument("file2")
    ap.add_argument("file3")
    ap.add_argument("--min", type=int, default=64, help="мінімальний розмір області (байти)")
    ap.add_argument("--chunk", type=int, default=1024 * 1024, help="chunk size (байти)")
    ap.add_argument("--hash", action="store_true", help="показувати sha256 для знайдених областей")
    ap.add_argument("--merge-gap", type=int, default=0,
                    help="зливати області якщо gap між ними <= N байт (0 = не зливати)")

    args = ap.parse_args()

    if args.min <= 0:
        print("min size має бути > 0")
        return 1

    if args.merge_gap < 0:
        print("merge-gap має бути >= 0")
        return 1

    compare_three_files(
        args.file1, args.file2, args.file3,
        min_size=args.min,
        chunk_size=args.chunk,
        show_hash=args.hash,
        merge_gap=args.merge_gap
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
