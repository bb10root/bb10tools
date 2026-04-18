#!/bin/bash
source ~/bbndk/bbndk-env_10_3_0_698.sh
ntoarmv7-gcc autorun.c -O2 -DNDEBUG -std=gnu99 -I ../include -o autorun
ntoarmv7-strip autorun