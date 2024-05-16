#!/bin/bash

gcc enc_dir_fuse.c ../utils/enc_utils.c -o enc_dir_fuse `pkg-config fuse --cflags --libs` -lsodium
cp ./enc_dir_fuse /usr/bin