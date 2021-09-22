#!/bin/bash
sudo make
sudo insmod proj2.ko int_str="1,2,3,4,5"
sudo rmmod proj2.ko
sudo dmesg | tail -20