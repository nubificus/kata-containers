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

sudo apt update && sudo apt install -y libssl-dev

go get -d -u github.com/nubificus/kata-containers
cd $GOPATH/src/github.com/nubificus/kata-containers
git checkout vaccel-release
COMMIT=$(git log -1 --pretty=format:%h)
sudo mkdir -p $OUTPUT_DIR/share/kata-containers/
OUTPUT_DIR=${EXPORT_PATH}/$COMMIT
cd tools/packaging/kernel
echo "CONFIG_MODULES=y" > configs/fragments/$ARCH_KERNEL/vaccel.conf
echo "CONFIG_MODULE_UNLOAD=y" >> configs/fragments/$ARCH_KERNEL/vaccel.conf
echo "CONFIG_MODULE_SIG=y" >> configs/fragments/$ARCH_KERNEL/vaccel.conf
VERSION=`./build-kernel.sh -f setup 2>&1 |grep Kernel\ version\: | awk '{print $4}'`
./build-kernel.sh build
if [[ $ARCH_KERNEL == "x86_64" ]]
then
	sudo cp kata-linux*/vmlinux $OUTPUT_DIR/share/kata-containers/vmlinux.container
else
	sudo cp kata-linux*/arch/$ARCH_KERNEL/boot/Image $OUTPUT_DIR/share/kata-containers/vmlinux.container
fi

cd /home/runner
git clone https://github.com/cloudkernels/virtio-accel.git && cd virtio-accel
#git checkout a compatible commit
COMMIT=$(git log -1 --pretty=format:%h)
KDIR=$GOPATH/src/github.com/nubificus/kata-containers/tools/packaging/kernel/kata-linux-*/ make ZC=0 ARCH=$ARCH_KERNEL
sudo cp virtio_accel.ko $OUTPUT_DIR/share/kata-containers/
sudo sh -c "echo $VERSION > $OUTPUT_DIR/share/kata-containers/KERNEL.version"
sudo sh -c "echo $COMMIT > $OUTPUT_DIR/share/kata-containers/VIRTIO_ACCEL.version"
sudo sh -c "echo Built for kernel $VERSION > $OUTPUT_DIR/share/kata-containers/VIRTIO_ACCEL.version"

set +x
