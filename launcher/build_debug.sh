#!/bin/bash
source ~/bbndk/bbndk-env_10_3_0_698.sh
python3 ../sig_gen.py -i signatures.txt -o signatures.h
ntoarmv7-gcc launcher.c -O0 -DDEBUG -std=gnu99 -fomit-frame-pointer -I../include -o launcher_patcher

