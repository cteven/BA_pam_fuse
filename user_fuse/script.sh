#!/bin/bash

gcc testfuse.c ../enc_utils/enc_utils.c -o testfuse `pkg-config fuse --cflags --libs` -lsodium
./testfuse -f ./test2