## [M1: point 1]
#  Explain following in here
#  Answer: Here we are defining the name of the module we are writing, storing it into a variable for future 
#  reference
#  ...
MODULE	 = ex3

## [M2: point 1]
#  Explain following in here
#  Answer: The kbuild system in kernel will build mod_name.o from mod_name.c After linking these files will 
#  get kernel module mod_name.ko.
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Explain following in here
#  Answer: The following line is used to point to the installed kernel files directory. uname -a command 
#  gives us the current running kernel version, which will be the directory name in the path 
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Explain following in here
#  Answer: pwd command gives the path to present working directory when run in shell. shell pwd returns the full path to the current working directory 
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  Explain following in here
#  Answer: We are defining what the target "all" should do in the following couple of lines. The variable MODULE has out module name
#  so all: our_module_name would help us make only our new module, as defined in the target $(MODULE) near line M7
#  ...
all: $(MODULE)


## [M6: point 1]
#  Explain following in here
#  Answer: defines a rule that can make any file x.o from x.c. The recipe uses the automatic variables ‘$@’ and ‘$<’ to substitute the 
#  names of the target file and the source file in each case where the rule applies. CC is the gcc compiler.  $< points to source file names
#  and $@ are the object file names
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  Explain following in here
#  Answer: Here we are defining the target rule $(MODULE) to build our specific module in the following recipie. KERNELDIR is the directory of kernel dependencies that are installed and to be used to build the module. PWD is the present working directory, MAKE is to use the make command. 
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Explain following in here
#  Answer: Here we are writing the target recipie clean to clean the residual/created objects from previous make runs. We are removing the module files from kernel directory as well as cleaning up the PWD
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
