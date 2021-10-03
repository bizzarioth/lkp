<<<<<<< Updated upstream
<<<<<<< Updated upstream
MODULE = perftop

obj-m += $(MODULE).o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
=======
=======
>>>>>>> Stashed changes
MODULE   = perftop

obj-m += $(MODULE).o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

PWD := $(shell pwd)

all: $(MODULE)

<<<<<<< Updated upstream
<<<<<<< Updated upstream

%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

=======
=======
>>>>>>> Stashed changes
%.o: %.c
        @echo "  CC      $<"
        @$(CC) -c $< -o $@

$(MODULE):
        $(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
<<<<<<< Updated upstream
        $(MAKE) -C $(KERNELDIR) M=$(PWD) clean
>>>>>>> Stashed changes
=======
        $(MAKE) -C $(KERNELDIR) M=$(PWD) clean
>>>>>>> Stashed changes
