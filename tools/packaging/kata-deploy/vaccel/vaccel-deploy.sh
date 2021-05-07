#!/usr/bin/env bash
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o pipefail
set -o nounset

vaccel_default_path="/opt/vaccel"
vaccel_path=${2:-$vaccel_default_path}
shim="fc"

# If we fail for any reason a message will be displayed
die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function print_usage() {
	echo "Usage: $0 [install/configure/cleanup]"
}


# Install vAccel artifacts on host.
# If vAccel artifacts are already present in the container image 
# (/opt/vaccel-artifacts) perform a copy to host vaccel default
# path. Otherwise we call the download script.

function install_artifacts() {
	echo "Installing vAccel artifacts on host"

	# if vAccel is already installed, then copy artifacts to host
	# otherwise try to call the vaccel downloader if present
	if [ -f "/opt/vaccel-artifacts/.downloaded" ]; then
		echo "vAccel is already installed in container image"
		echo "Copying from container to host ${vaccel_path}"
		cp -a /opt/vaccel-artifacts/* ${vaccel_path}
	else
		if ! [ -x "$(command -v vaccel-download)" ]; then
			die "vAccel downloader not installed"
		else
			echo "Downloading vAccel on ${vaccel_path}"
			vaccel-download ${vaccel_path}
			echo "Finished downloading vAccel"
		fi
	fi

	echo "Installing vAccel runtime to host"
	# Hypervisor (Firecracker vAccel Virtio) and vaccelrt-agent binaries are linked
	# against Vaccel Runtime. Create a link to libvaccel.so in a systems runtime
	# library path (usr/local/lib)
	local libvaccel_link="/usr/local/lib/libvaccel.so"
	if [ -L "${libvaccel_link}" ]; then
		echo "warning: /usr/local/lib/libvaccel.so already exists"
	else	
		ln -sf ${vaccel_path}/lib/libvaccel.so /usr/local/lib/libvaccel.so
	fi
	echo "Finished vAccel artifacts installation on host"
}


function configure_env() {
	# Configure vaccel environment variables for Firecracker
	echo "Configure environment for Firecracker vAccel"
	
	#VACCEL_BACKENDS=${vaccel_path}/lib/libvaccel-${vaccel_backend}.so

	# These are backend specific. Hardcode for now.
	#CUDA_CACHE_PATH=/tmp/
	#VACCEL_IMAGENET_NETWORKS=${vaccel_path}/share/data/networks
	
	#Add the environment variables to containerd-shim-kata-fc-v2 script. This script is the "parent" of the Firecracker process.
	
	local shim_binary="containerd-shim-kata-${shim}-v2"
	local shim_file="/usr/local/bin/${shim_binary}"
	local shim_backup="/usr/local/bin/${shim_binary}.bak"

	if [ -f "${shim_file}" ]; then
		echo "warning: ${shim_binary} already exists" >&2
		if [ ! -f "${shim_backup}" ]; then
			mv "${shim_file}" "${shim_backup}"
		else
			rm "${shim_file}"
		fi
	fi
       cat << EOT | tee "$shim_file"
#!/bin/bash
KATA_CONF_FILE=/opt/kata/share/defaults/kata-containers/configuration-${shim}.toml /opt/kata/bin/containerd-shim-kata-v2.vaccel \$@
EOT
	chmod +x "$shim_file"
	echo "Done! containerd-shim-kata-v2 is now configured to run Firecracker with vAccel"
}

function remove_artifacts() {
	echo "deleting libvaccel.so link from /usr/local/lib"
	rm -f /usr/local/lib/libvaccel.so 
	echo "deleting vAccel artifacts"
	rm -rf /opt/vaccel/*
	rm -f /opt/vaccel/.download*
}


function main() {
	# script requires that user is root
	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die  "This script must be run as root"
	fi

	action=${1:-}
	if [ -z "$action" ]; then
		print_usage
		die "invalid arguments"
	fi

	case "$action" in
		install)
			install_artifacts
			;;
		configure)
			configure_env
			;;
		cleanup)
			remove_artifacts
			;;
		*)
			echo invalid arguments
			print_usage
			;;
	esac

}

main "$@"
