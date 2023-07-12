#!/bin/bash

unset unikernel
unset image
unset image_tar
clean="0"

display_help() {
    echo "Build an OCI container image containing only the unikernel binary."
    echo
    echo "Syntax: $0 [-u|-i|-c|-h]"
    echo "---------------------"
    echo "Usage:"
    echo
    echo "  -u  BINARY   Specify the unikernel binary you want to package."
    echo "  -i  IMAGE    Specify the name of the image you want to create."
    echo "  -c           If set, the script will delete the .tar of the bundle after importing to ctr."
    echo "  -h           Print this help."
}

create_dockerfile () {
    echo "Creating Dockerfile"
    cat <<EOF >./Dockerfile
FROM scratch
COPY $1 /unikernel/
EOF
}

delete_dockerfile () {
    rm -f ./Dockerfile
}

build_docker_image () {
    sudo docker build -t $1 -f Dockerfile .
}

export_docker_image () {
    IN=$1
    partsIN=(${IN//// })
    last="${partsIN[0]##* }"
    last="$last.tar"
    sudo docker save -o $last $1
    image_tar=$last
}

import_ctr_image () {
    sudo ctr images import $1
}

delete_image_tar () {
    rm -f $1
}

check_dependencies() {
    have_docker=$(which docker)
    have_ctr=$(which ctr)

    to_install=""

    if [ -z "$have_docker" ]; then
        to_install="$to_install docker "
    fi

    if [ -z "$have_ctr" ]; then
        to_install="$to_install ctr "
    fi

    if [ -z "$to_install" ]; then
        echo "OK" >/dev/null
    else
        echo "$0 cannot run without the following dependencies:"
        echo "$to_install"
        echo
        echo "Please install them and try again."
        exit 1
    fi
}

check_dependencies

while getopts ":hu:i:ce:" option; do
    case $option in
    h) # display Help
        display_help
        exit
        ;;
    u) unikernel=${OPTARG} ;;
    i) image=${OPTARG} ;;
    c) clean="true" ;;
    e) extrafile=${OPTARG} ;;
    :) # If expected argument omitted:
        echo "Error: -${OPTARG} requires an argument."
        echo "Try '$0 -h' for more information."
        exit 1
        ;;
    \?)
        echo "Error: Invalid option"
        echo "Try '$0 -h' for more information."
        exit 1
        ;;
    esac
done

if [ ! "$unikernel" ] || [ ! "image" ]; then
    echo "arguments -u and -i must be provided"
    echo "Use '$0 -h' for more information."
    exit 1
fi

if [[ "$image" =~ .*":".* ]]; then
  echo "It's there."
else
    echo "Tag not specified. Tagging as latest."
    image="$image:latest "
fi

create_dockerfile $unikernel $extrafile
build_docker_image $image
export_docker_image $image
delete_dockerfile
import_ctr_image $image_tar
if [ "$clean" == "true" ]; then
    delete_image_tar $image_tar
fi
