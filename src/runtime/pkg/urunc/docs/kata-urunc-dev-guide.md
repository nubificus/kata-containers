# Instructions / Commands for kata-urunc dev

## Dev environment setup

This assumes you already have a working kata-qemu installation (following the blog posts' instructions). If this is not the case, you may need to edit some directories accordingly.

First we need to get the source code and build the `containerd-shim` binary:

```bash
export PATH=$PATH:$(go env GOPATH)/bin && \
  export GOPATH=$(go env GOPATH) && \
  export GO111MODULE=off

go get -d -u github.com/nubificus/kata-containers
pushd $GOPATH/src/github.com/nubificus/kata-containers/src/runtime
git switch unikernels-support # or git switch -c unikernels-support
export GO111MODULE=on
export PREFIX=/opt/unikata
make
sudo -E PATH=$PATH -E PREFIX=$PREFIX make install
sudo mv /opt/unikata/bin/containerd-shim-kata-v2 /opt/unikata/containerd-shim-kata-unikernels-v2
sudo rm -rf /opt/unikata/bin && sudo rm -rf /opt/unikata/share
sudo ln -s /opt/unikata/containerd-shim-kata-unikernels-v2 /usr/local/bin
popd
```

Next we need to create a valid config file. For now, this is done by copying the QEMU config file and adding an extra `unikernel` option:

```bash
sudo cp /opt/kata/configs/configuration.toml /opt/kata/configs/configuration-urunc.toml
```

Add a single line at the end of the hypervisor section:

```
unikernel = true
```

Create a new file somewhere in PATH eg: `/usr/local/bin/containerd-shim-kata-urunc-v2` and add the followning lines:

```bash
#!/bin/bash
KATA_CONF_FILE=/opt/kata/configs/configuration-urunc.toml /usr/local/bin/containerd-shim-kata-unikernels-v2 $@
```

Then make it executable.

Finally, add the following lines to the containerd config file:

```
[plugins.cri.containerd.runtimes]
  [plugins.cri.containerd.runtimes.kata-urunc]
    runtime_type = "io.containerd.kata-urunc.v2"
```

Restart `containerd`:

```bash
sudo systemctl restart containerd
```

## Recompile:

After any changes, you can recompile the binary using the following commands. It is helpful if you place them in a simple script:

```bash
export PATH=$PATH:$(go env GOPATH)/bin && \
  export GOPATH=$(go env GOPATH)

pushd $GOPATH/src/github.com/nubificus/kata-containers/src/runtime
git switch unikernels-support # or git switch -c unikernels-support
export GO111MODULE=on
export PREFIX=/opt/unikata
make
sudo -E PATH=$PATH -E PREFIX=$PREFIX make install
sudo mv /opt/unikata/bin/containerd-shim-kata-v2 /opt/unikata/containerd-shim-kata-unikernels-v2
sudo rm -rf /opt/unikata/bin && sudo rm -rf /opt/unikata/share
popd
```

## Logs

All logs added to this branch have a `src` field with the value `uruncio`. We can use this to filter the syslog.
Furthermore, some log entries appear twice, due to `containerd` and `kata` both logging them.

```bash
# To avoid duplicates use:
cat /var/log/syslog | grep uruncio | grep -F kata[ 
# or
cat /var/log/syslog | grep uruncio | grep -F containerd[ 

# You can also omit the second grep to see the full picture
cat /var/log/syslog | grep uruncio

cat /var/log/syslog | grep -v uruncio

```

To purge the logs:

```bash
sudo su -c '> /var/log/syslog'
```

## Run test containers:

To run a test container, we need to get the image and run it using the `kata-urunc` runtime:

```bash
sudo ctr images pull docker.io/library/ubuntu:latest
sudo ctr run --runtime io.containerd.run.kata-urunc.v2 -t --rm docker.io/library/ubuntu:latest ubuntu-kata-test uname -a
sudo ctr run --runtime io.containerd.run.kata.v2 -t --rm docker.io/library/ubuntu:latest ubuntu-kata-test uname -a

sudo ctr run --runtime io.containerd.run.kata-urunc.v2 -t --rm docker.io/urunc/testhello:latest urunc-kata-test /unikernel/hello
```


### Clean up

```bash
sudo pkill -f ubuntu-kata-test ;\
  sudo ctr c rm ubuntu-kata-test ;\
  sudo ctr snapshot rm ubuntu-kata-test ;\
  sudo systemctl restart containerd ;\
  sudo rm -rf /run/containerd/io.containerd.runtime.v2.task/default/ubuntu-kata-test
```

```bash
sudo pkill -f urunc-kata-test ;\
  sudo ctr c rm urunc-kata-test ;\
  sudo ctr snapshot rm urunc-kata-test ;\
  sudo systemctl restart containerd ;\
  sudo rm -rf /run/containerd/io.containerd.runtime.v2.task/default/urunc-kata-test
```

## Clean up dead containers

During this whole process many things fail, so it often is required to clean up the dead containers:

```bash
sudo ctr snapshots rm ubuntu-kata-test
sudo ctr c rm ubuntu-kata-test
# sometimes we need to kill the processes before removing the container
ps ax | grep ubuntu-kata-test
sudo kill ... ... ...
```
## Custom image creation 

To create a custom image containing a single unikernel binary, you can use the `image-builder/build.sh` script.

```bash
cd nubificus/kata-containers/src/runtime/pkg/urunc/image-builder

# To see the help message:
./build.sh -h

# Create a urunc/testhello image containing a hello
# and import it to ctr
./build.sh -u hello -i urunc/testhello -c

# Create a urunc/testhello image containing a hello
# import it to ctr and keep the budnle .tar file
./build.sh -u hello -i urunc/testhello
```
