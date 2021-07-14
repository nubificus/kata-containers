#!/bin/bash

set -x
EXPORT_DEFAULT_DIR="/store/runner-output/kata-containers"
EXPORT_PATH=${EXPORT_DIR:-$EXPORT_DEFAULT_DIR}

export GOROOT=/usr/local/go
export GOPATH=/home/runner/go
export PATH=$GOROOT/bin:$PATH

go get -d -u github.com/nubificus/kata-containers
cd $GOPATH/src/github.com/nubificus/kata-containers
git checkout vaccel-release
COMMIT=$(git log -1 --pretty=format:%h)
OUTPUT_DIR=$EXPORT_PATH/$COMMIT
sudo mkdir -p $OUTPUT_DIR/bin
sudo mkdir -p $OUTPUT_DIR/share/defaults/kata-containers/
make -C src/runtime
sudo cp src/runtime/containerd-shim-kata-v2 $OUTPUT_DIR/bin/
sudo cp src/runtime/cli/config/configuration-fc.toml $OUTPUT_DIR/share/defaults/kata-containers

set +x
