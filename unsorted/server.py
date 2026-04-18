#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import socket
import struct

HOST = "0.0.0.0"
PORT = 12345
DUMP_DIR = "./dumps"
CHUNK_SIZE = 64*1024

MSG_META = 1
MSG_SEG  = 2
MSG_LOG  = 3
MSG_DONE = 0xFF

MSG_MAGIC = 0x50454455  # "PEDU"

os.makedirs(DUMP_DIR, exist_ok=True)

def pid_dir(pid):
    d = os.path.join(DUMP_DIR, f"pid_{pid}")
    os.makedirs(d, exist_ok=True)
    return d


def recvn(conn, n):
    """Read exactly n bytes from socket"""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buf += chunk
    return buf

def handle_client(conn):
    try:
        while True:
            # Read message header
            hdr_data = recvn(conn, 12)  # msg_hdr_t: uint32 magic, uint16 type, uint16 version, uint32 len
            magic, type_, version, length = struct.unpack(">IHHI", hdr_data)
            if magic != MSG_MAGIC:
                print("[!] Invalid magic, closing connection")
                break

            body = recvn(conn, length) if length else b""

            if type_ == MSG_SEG:
                if len(body) != 36:
                    print("[!] Invalid MSG_SEG length")
                    continue
                pid, vaddr, size, flags, dev, ino = struct.unpack(">IQQIIQ", body)
                pdir = pid_dir(pid)
                fname = os.path.join(pdir, f"seg_0x{vaddr:X}.bin")

                print(f"[+] Receiving segment: pid={pid}, vaddr=0x{vaddr:X}, size={size}, flags={flags:X}, dev={dev:X}, ino={ino:X}")

                remaining = size
                with open(fname, "wb") as f:
                    while remaining > 0:
                        chunk = conn.recv(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            print("[!] Connection closed mid-segment")
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                    f.flush()
                print(f"[+] Segment saved to {fname}")

            elif type_ == MSG_META:
                print(f"[META] {body.decode(errors='ignore')}")
            elif type_ == MSG_LOG:
                if len(body) < 4:
                    print("[!] Invalid MSG_LOG length")
                    continue
                pid = struct.unpack(">I", body[:4])[0]
                text = body[4:].decode(errors='ignore')
                #print(f"[LOG] pid={pid}: {text}")

                # write to file
                pdir = pid_dir(pid)
                log_fname = os.path.join(pdir, "log.txt")

                with open(log_fname, "a") as f:
                    f.write(text)
                    if not text.endswith("\n"):
                        f.write("\n")
                    f.flush()
            elif type_ == MSG_DONE:
                print("[+] Done receiving data")
                break
            else:
                print(f"[!] Unknown message type {type_}, length={length}")

    except ConnectionError as e:
        print(f"[!] Connection error: {e}")
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[+] Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[+] Connection from {addr}")
            handle_client(conn)
            print("[+] Client disconnected")

if __name__ == "__main__":
    main()
