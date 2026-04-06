# The loader (main) needs to be position-independant, otherwise the loader and the file to
# load (dummy) would be loaded onto the same offset => crash!
all:
	gcc -I/usr/include/x86_64-linux-gnu -DOS_LINUX -DARCH_X86_64 elf.c main.c -o main_64 -pie -fPIC -lcurl

clean:
	rm main_64
