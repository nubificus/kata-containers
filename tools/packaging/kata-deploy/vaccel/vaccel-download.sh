#!/bin/bash
RELEASE="0.0.1"
VACCEL_ARTIFACTS_URL="https://github.com/nubificus/docs/releases/download/${RELEASE}/vaccel-libs.tar.xz"
VACCEL_DEFAULT_PATH="/opt/vaccel"
VACCEL_PATH=${1:-$VACCEL_DEFAULT_PATH}

echo "vAccel downloader script is running: ${VACCEL_PATH}"

VACCEL_IMAGE_NETWORKS_PATH=${VACCEL_PATH}/share/data/networks

wget -N -q -P ${VACCEL_PATH} ${VACCEL_ARTIFACTS_URL}
echo "exporting tar: ${VACCEL_PATH}/vaccel-libs.tar.xz"
tar xf ${VACCEL_PATH}/vaccel-libs.tar.xz -C ${VACCEL_PATH} 
#rm -f ${VACCEL_PATH}/vaccel.tar

wget -N -q -P ${VACCEL_IMAGE_NETWORKS_PATH} https://raw.githubusercontent.com/nubificus/jetson-inference/master/data/networks/detectnet.prototxt
wget -N -q -P ${VACCEL_IMAGE_NETWORKS_PATH} https://raw.githubusercontent.com/nubificus/jetson-inference/master/data/networks/ilsvrc12_synset_words.txt
wget -N -q -P ${VACCEL_IMAGE_NETWORKS_PATH} https://raw.githubusercontent.com/nubificus/jetson-inference/master/data/networks/ssd_coco_labels.txt
wget -N -q -P ${VACCEL_IMAGE_NETWORKS_PATH}/.. https://raw.githubusercontent.com/dusty-nv/jetson-inference/master/tools/download-models.sh

cd ${VACCEL_IMAGE_NETWORKS_PATH}/..
# remove this flag or older versions of wget may fail
sed -e "s/--show-progress//g" -i.backup download-models.sh
chmod +x download-models.sh

#mkdir -p networks
if [[ ! -f networks/.downloaded ]]; then
	echo "Downloading Jetson inference models on ${VACCEL_IMAGE_NETWORKS_PATH} "
	./download-models.sh NO
	[[ $? -eq 0 ]] && touch networks/.downloaded
fi

# Use this file as notification in case kata-vaccel daemon is used 
touch ${VACCEL_PATH}/.downloaded
echo "vAccel downloader exiting..."
