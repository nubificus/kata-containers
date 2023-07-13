# Instructions to setup kata-urunc for local dev

> **_NOTE:_**  This guide works best for Ubuntu 20.04 Linux distributions.

In order to setup kata-urunc for local development we need to perform the following steps:

### Step 1: Fetsing all dependencies and tools

The kata-urunc has been tested using Go v1.17.10 and for setting it up, we will need some other apt/snap packages, such as containerd, gcc make etc.

At first, let's get all the apt/snap packages that are needed.

```
sudo apt update && sudo apt upgrade -y
sudo apt install gcc g++ make containerd runc snapd -y
sudo snap install yq --channel=v3/stable
```

Secondly, we need to get the Go v1.17.10:

```
down_dir=$(mktemp -d)
pushd $down_dir
wget -q https://go.dev/dl/go1.17.10.linux-$(dpkg --print-architecture).tar.gz
sudo mkdir -p /usr/local/go1.17
sudo tar -C /usr/local/go1.17 -xzf go1.17.10.linux-$(dpkg --print-architecture).tar.gz
echo 'export PATH=$PATH:/usr/local/go1.17/go/bin' >> $HOME/.profile
source $HOME/.profile
popd
rm -rf $down_dir
```

Moreover, we will need to install Docker, since it is used from some build scripts.

```
singudo apt-get remove docker docker-engine docker.io containerd runc -y
sudo rm -rf /var/lib/docker/
down_dir=$(mktemp -d)
pushd $down_dir
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
popd
rm -rf $down_dir
```

At last, we will install nerdctl for testing kata-urunc. Unfortunately, the ctr tool does not work well with kata-containers. In particular, there are some issues on creating the network (See: https://github.com/kata-containers/kata-containers/issues/2580).
The suggested versions are 
- CNI: v1.1.1
- NERDCTL: v0.20.0

```
down_dir=$(mktemp -d)
pushd $down_dir
#CNI
CNI_VERSION=1.1.1
wget https://github.com/containernetworking/plugins/releases/download/v$CNI_VERSION/cni-plugins-linux-amd64-v$CNI_VERSION.tgz
mkdir -p /opt/cni/bin #This might need sudo
tar Cxzvf /opt/cni/bin cni-plugins-linux-amd64-v$CNI_VERSION.tgz #This might need sudo

#NERDCTL
NERDCTL_VERSION=0.20.0 
wget https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz
tar Cxzvvf /usr/local/bin nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz #This might need sudo
popd
rm -rf $down_dir
```

### Step 2: Building and installing kata-urunc

We will build the kata-urunc, using the Go version we downloaded previously.

```
export PATH=$PATH:$(go env GOPATH)/bin
export GOPATH=$(go env GOPATH)
git clone https://github.com/TUM-DSE/FPGA-uruntime.git -b urunc_funky
pushd FPGA-uruntime/src/runtime
export GO111MODULE=on
export PREFIX=/opt/kata
make
```

We will install the kata-urunc in `/opt/kata` as defined by `PREFIX`
```
sudo -E PATH=$PATH -E PREFIX=$PREFIX make install
popd
```

All the binaries are now placed in `/opt/kata/bin` and config files are placed in `/opt/kata/share/defaults/kata-containers/`.

Moreover, in order to avoid any confusions, we change the name of the generated containerd-shim and create a link to `/usr/local/bin`:

```
sudo mv /opt/kata/bin/containerd-shim-kata-v2 /opt/kata/containerd-shim-kata-unikernels-v2
sudo ln -s /opt/kata/containerd-shim-kata-unikernels-v2 /usr/local/bin
```

### Step 3: Building and installing the ukvm hypervisor

```
git clone https://github.com/TUM-DSE/funky-monitor.git
cd funky-monitor
make
```

It is ismportant to note that nerdctl and such tools will fail to capture the output of a very short-lived unikernel such as a Hello world example. For that reason, to just verify that everything works correctly, we advice to add an infinite loop before the end of the Hello world exmaple under `<funky_monitor_repo_root>/tests/test_hello/test_hello.c`. After the changes, we should rebuild the unikernel.

```
#In Funky monitor's repo root
make
```

The kata-urunc expects the ukvm monitor to be placed under `/opt/kata/bin` with the name `solo5-hvt`. However, this will change in the future.

```
#In Funky monitor's repo root
cp ./ukvm/ukvm-bin /opt/kata/bin #It might reuire sudo
```

### Step 4: Configuring kata-urunc

*A working configuration for kata-urunc can be found in [configuration-urunc.toml](../urunc_configs/configuration-urunc.toml).*

The configuration for kata-urunc can be based on the QEMU's one for Kata containers.
```
cp /opt/kata/share/defaults/kata-containers/configuration-qemu.toml /opt/kata/share/defaults/kata-containers/configuration-urunc.toml
```

However the following changes are necessary:
1. In the hypervisor section definition we need to replace qemu with urunc.
2. In the hypervisor section we should add the `unikernel = true` line.


At last we need to create a new script, which will invoke the configuration. For that purpose, we can create a new file `/usr/local/bin/containerd-shim-kata-urunc-v2`, which will contain the following lines:
```
#!/bin/bash
KATA_CONF_FILE=/opt/kata/share/defaults/kata-containers/configuration-urunc.toml /usr/local/bin/containerd-shim-kata-unikernels-v2 $@
```

This file should have execution permissions:
```
chmod +x /usr/local/bin/containerd-shim-kata-urunc-v2 #It might need sudo
```

### Step 5: Configuring containerd

*A working configuration for containerd can be found in [containerd\_config.toml](../urunc_configs/containerd_config.toml). Keep in mind that this is a complete configuration, which includes devmapper too. If you have not set up devmapper yet, then you might want to remove the respective section from the configuration.*

In this step, we will add the necessary configuration for our new runtime in containerd. Therefore, we append the following lines in the containerd's config file at `/etc/containerd/config.toml`

```
[plugins.cri.containerd.runtimes]
  [plugins.cri.containerd.runtimes.kata-urunc]
    runtime_type = "io.containerd.kata-urunc.v2"
```

> **_NOTE:_**  We should aslo make sure that the cri plugin is not disabled in the config file. The disabled_plugins filed should not contain cri

The changes will take place after we restart the containerd service:

```
sudo systemctl restart containerd
```

## The first test

At this time we can perform a first test and verify that everything has worked well.
The kata-urunc runtime should be execute a simple binary. However, at first we need to create
an OCI image for that binary. This can be done by the build script that kata-urunc offers.
The script is located in the `<path_to_repo_root>/src/runtime/pkg/urunc/image-builder` directory.
This directory also includes a binary file named `hello` and its source code `hello.c`.
We will use this binary for our test.

```
#From the root of kata-urunc repo
cd src/runtime/pkg/urunc/image-builder
./build.sh -u ./hello -i binary/hello
```
The build script will generate a docker image with the name that we gave as an argument for `-i` option.
We can list all the images we have in our system with the followin command:
```
sudo nerdctl image ls
```

After building the image we can deploy it using the following command:

```
sudo nerdctl --cni-path=/opt/cni/bin  run --runtime io.containerd.run.kata-urunc.v2 -it --rm binary/hello:latest
```

The output of the above command should be the following message:
```
Hello, World!
```

### Step 6: Configuring devmapper

The kata-urunc runtime uses the devmapper to get any block devices from the image that contains the unikernel. As a result, we need to properly set up and configure devmapper.

The [devmapper\_create.sh](../urunc_scripts/devmapper_create.sh) script can set up the devmapper for us and it will provide us the necessary additions for containerd configuration.

```
bash <kata-urunc-root-repo>/scripts/devmapper_create.sh
```

At the end the script will output the necessary configuration for devmapper, that we need to append in containerd's configuration. For instance:
```
#
# Add this to your config.toml configuration file and restart containerd daemon
#
[plugins]
  [plugins.devmapper]
    pool_name = "containerd-pool"
    root_path = "/var/lib/containerd/io.containerd.snapshotter.v1.devmapper"
    base_image_size = "10GB"
    discard_blocks = true
```

After updating the containerd config file, we need to restart the container service.
```
sudo systemctl restart containerd
```

Keep in mind that the devmapper will get destroyed if we shut down our machine. If we want to bring it up in the next boot, we will need to execute the [devmapper\_run.sh](../urunc_scripts/devmapper_run.sh) script, which will recreate the thin-pool in the same directory and as a result, we will not have to modify the containerd configuration.
Alternatively, we can create a systemd service to execute the above script on each reboot. For that purpose, we need to create a new file `/lib/systemd/system/devmapper_reload.service` with the following content:
```
[Unit]
Description=Devmapper reload script

[Service]
ExecStart=/path/to/script/reload.sh

[Install]
WantedBy=multi-user.target
```

Finally, we need to enable the new service:
```
sudo systemctl daemon-reload
sudo systemctl enable devmapper_reload.service
sudo systemctl start devmapper_reload.service
```

### The final test

If everything worked out of the box, we should be able to spawn our unikernel and get its output.
However, at first we need to build the unikernel in a docker image. For that purpose, we will
use the build script from kata-urunc.

```
#From the root of kata-urunc repo
cd src/runtime/pkg/urunc/image-builder
cp <path_to_funky_monitor>/tests/test_hello/test_hello.ukvm test_hello.hvt
./build.sh -u ./test_hello.hvt -i hvt/test_hello
```

> **_NOTE:_**  The suffix of the unikernel image should be hvt, since the suffix is used from the kata-urunc to identify the unikernel type.

After building the docker image, we should be able to spawn our unikernel.

```
sudo nerdctl --cni-path=/opt/cni/bin  run --snapshotter devmapper --runtime io.containerd.run.kata-urunc.v2 -it --rm hvt/test_hello:latest
```
## Rebuilding and reinstalling kata-urunc

After any changes in the source code of kata-urunc, we can rebuild and reinstall the updated version by simply following the steps in Step 2.

## Logging

Debugging a container runtime is not an easy process.The typical way to do that is by printing logs, using the log system from Kata containers. As a result, all the logs will be stored in `/var/log/syslog`.
In order toretrive the kata-urunc specific logs, we can filter the syslog file, using the uruncio word. Note that the logs will be duplicated, since are printed by both containerd and Kata.

```
# To avoid duplicates use:
cat /var/log/syslog | grep uruncio | grep -F kata[ 
# or
cat /var/log/syslog | grep uruncio | grep -F containerd[ 
```
