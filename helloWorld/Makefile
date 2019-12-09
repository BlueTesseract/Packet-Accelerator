obj-m += hello.o

all:
	make -C ../modinst/lib/modules/5.1.0-00108-g5c21be71d13b/build ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KBUILD_DEBARCH=armhf M=$(PWD) modules

clean:
	make -C ../modinst/lib/modules/5.1.0-00108-g5c21be71d13b/build ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- KBUILD_DEBARCH=armhf M=$(PWD) clean
