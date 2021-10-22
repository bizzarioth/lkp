#!/bin/bash
make
sudo insmod perftop.ko
#sudo dmesg| tail -100
echo "-----Waiting 10 Seconds"
sleep 10s
echo "#--PROC_FILE--#"
cat /proc/perftop
echo "#-------------#"
sudo rmmod perftop.ko
echo "Removing Kprobe"
sudo make clean
