#!/bin/bash
make
sudo insmod proj2.ko int_str="1,2,3,4,5"
sudo dmesg| tail -100
echo "---PROC FILE---"
cat /proc/proj2
echo "---PROC ENDS---"
sudo rmmod proj2.ko
<<<<<<< Updated upstream
<<<<<<< Updated upstream
sudo make clean
=======
sudo make clean
>>>>>>> Stashed changes
=======
sudo make clean
>>>>>>> Stashed changes
