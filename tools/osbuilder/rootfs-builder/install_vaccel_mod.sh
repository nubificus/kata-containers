#!/bin/bash

MODULES_DIR=${ROOTFS_DIR}/lib/modules/5.10.25

mkdir -p ${MODULES_DIR}
cp /store/ananos/virtio-accel/virtio_accel.ko ${MODULES_DIR}
touch ${MODULES_DIR}/modules.builtin
touch ${MODULES_DIR}/modules.order
chroot ${ROOTFS_DIR} depmod 5.10.25
