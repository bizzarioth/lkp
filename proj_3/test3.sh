#!/bin/bash
make
sudo insmod perftop.ko
#sudo dmesg| tail -100
echo "#--PROC_FILE--#"
cat /proc/perftop
echo "#-------------#"
sudo rmmod perftop.ko
echo "Removing Kprobe"
sudo make clean
