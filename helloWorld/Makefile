obj-m += hello.o

all:
	make -C ../linux-socfpga ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KBUILD_DEBARCH=armhf M=$(PWD) modules

clean:
	make -C ../linux-socfpga ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KBUILD_DEBARCH=armhf M=$(PWD) clean
