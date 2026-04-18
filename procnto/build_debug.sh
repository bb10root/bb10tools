#!/bin/bash
source ~/bbndk/bbndk-env_10_3_0_698.sh
python3 ../sig_gen.py -i nto.txt -o nto_sig.h
ntoarmv7-gcc procnto_patch.c -O0 -DDEBUG -std=gnu99 -I../include -I../include/mmc -o procnto_patch
