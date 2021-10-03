<<<<<<< HEAD

MODULE	 = proj2
=======
MODULE	 = ex4
>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea

obj-m += $(MODULE).o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

all: $(MODULE)

<<<<<<< HEAD
=======

>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
