<<<<<<< Updated upstream
MODULE = perftop

obj-m += $(MODULE).o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
=======
MODULE   = perftop

obj-m += $(MODULE).o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
>>>>>>> Stashed changes

PWD := $(shell pwd)

all: $(MODULE)

<<<<<<< Updated upstream

%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

=======
%.o: %.c
        @echo "  CC      $<"
        @$(CC) -c $< -o $@

$(MODULE):
        $(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
        $(MAKE) -C $(KERNELDIR) M=$(PWD) clean
>>>>>>> Stashed changes
