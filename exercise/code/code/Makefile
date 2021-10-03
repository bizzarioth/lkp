## [M1: point 1]
#  Explain following in here
#	A variable MODULE has been created, in which we have defined the name of the module
#  ...
MODULE	 = ex3

## [M2: point 1]
#  Explain following in here
#	This is used to link C files and compile the object files(.o)
#	In this case Module=ex3, hence we are linking ex3.c and corresponding object file will be ex3.o
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Explain following in here
#	This command checks if the Var KERNELDIR is already set to a value or not. If it is empty(not set), it will be be set to the specified value
#	The value pointed is the installed kernel files directory of the current running kernel version.
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Explain following in here
#	This sets the current Working Directory when executing in the shell.
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  Explain following in here
#	Here the the behavior of make target 'all' is being defined
#	$ is used to run a rule in the shell command.
#	Hence $(MODULE) will make the recipe MODULE as shell command
# invoked using make all in the shell
#  ...
all: $(MODULE)


## [M6: point 1]
#  Explain following in here
#	This line is used match and enforce created object filenames to their respective .c files
#	The filenames of the .o and .c will match
#	Causes recompilation if any c file is newer than existing .o file.
# The next lines use wildcards to include the first pre-requisite filename from the target list
#	CC is the gcc compiler and $< points to filenames, while $@ will link the .o files
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  Explain following in here
#	Here the the behavior of make Rule 'MODULE' is being defined
#	$ is used to run a rule in the shell command.
#	Hence $(MODULE) will make the target MODULE below
#	This translates to shell command:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Explain following in here
#	Here the the behavior of make target 'clean' is being defined
#	This will clean the residual files/objects created by a previous make run.
#	Here it will also remove the files created in the kernel build directory.
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
