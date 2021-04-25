#!/bin/bash
qemu-system-aarch64 \
-machine virt -cpu cortex-a57 \
-nographic -smp 4 -m 2048 \
-kernel arch/arm64/boot/Image \
-initrd ../rootfs.cpio \
-append "console=ttyAMA0"
