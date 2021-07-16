#!/bin/bash

set -x
EXPORT_DEFAULT_DIR="/store/runner-output/kata-containers"
EXPORT_PATH=${EXPORT_DIR:-$EXPORT_DEFAULT_DIR}
export GOROOT=/usr/local/go
export GOPATH=/home/runner/go
export PATH=$GOROOT/bin:$PATH
ARCHITECTURE=$(uname -m)
if [[ $ARCHITECTURE == "x86_64" ]]
then
 	export ARCH=amd64
	export ARCH_KERNEL=x86_64
elif [[ $ARCHITECTURE == "aarch64" ]]
then
	export ARCH=aarch64
	export ARCH_KERNEL=arm64
else
	echo "Architecture $ARCHITECTURE not supported"
	exit
fi

sudo apt update && sudo apt install -y libssl-dev qemu-utils parted debootstrap udev kmod coreutils libelf-dev

go get -d -u github.com/nubificus/kata-containers
cd $GOPATH/src/github.com/nubificus/kata-containers
git checkout vaccel-release
COMMIT=$(git log -1 --pretty=format:%h)
OUTPUT_DIR=$EXPORT_PATH/$COMMIT
sudo mkdir -p $OUTPUT_DIR/share/kata-containers/
VERSION=$(cat $OUTPUT_DIR/share/kata-containers/KERNEL.version)

cd tools/osbuilder/rootfs-builder
export ROOTFS_DIR=$PWD/rootfs
rm -rf $ROOTFS_DIR
script -fec 'sudo su root -c ". /opt/cargo/env && GOPATH=$GOPATH GOROOT=$GOROOT PATH=$GOROOT/bin:$PATH RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH ./rootfs.sh -r $ROOTFS_DIR ubuntu"'
VERSION=$(cat ${OUTPUT_DIR}/share/kata-containers/VIRTIO_ACCEL.version | grep kernel | awk '{print $4}')
MODULES_DIR=${ROOTFS_DIR}/lib/modules/$VERSION
sudo mkdir -p ${MODULES_DIR}
sudo cp $OUTPUT_DIR/share/kata-containers/virtio_accel.ko $MODULES_DIR
sudo touch ${MODULES_DIR}/modules.builtin
sudo touch ${MODULES_DIR}/modules.order
sudo sh -c "echo "virtio_accel" >> ${ROOTFS_DIR}/etc/modules"
sudo chroot ${ROOTFS_DIR} /sbin/depmod $VERSION
cd ../image-builder
script -fec 'sudo bash -x ./image_builder.sh $ROOTFS_DIR'
sudo cp kata-containers.img $OUTPUT_DIR/share/kata-containers/kata-containers.img.virtio

set +x
