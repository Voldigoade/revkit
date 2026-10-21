# Minimal x86-64

A Linux x86-64 program that exits with status zero. Assemble with `nasm -f elf64 minimal.asm -o minimal.o`, then link with `ld minimal.o -o minimal`. It performs no file or network access.
