#!/bin/bash -xe

INPUT_PATH=$1
VERSION=$2
OUTPUT_PATH=${3:-.}

PACKAGE_NAME=indy-anoncreds
POSTINST_TMP=postinst-${PACKAGE_NAME}
PREREM_TMP=prerm-${PACKAGE_NAME}

# copy the sources to a temporary folder
TMP_DIR=$(mktemp -d)
cp -r ${INPUT_PATH}/. ${TMP_DIR}

# prepare the sources
cd ${TMP_DIR}/build-scripts/ubuntu-1604
./prepare-package.sh ${TMP_DIR} ${VERSION}

# build the package

sed -i 's/{package_name}/'${PACKAGE_NAME}'/' 'postinst'
sed -i 's/{package_name}/'${PACKAGE_NAME}'/' 'prerm'

fpm --input-type "python" \
    --output-type "deb" \
    --verbose \
    --architecture "amd64" \
    --python-package-name-prefix "python3" \
    --python-bin "/usr/bin/python3" \
    --exclude "*.pyc" \
    --exclude "*.pyo" \
    --maintainer "Hyperledger <hyperledger-indy@lists.hyperledger.org>" \
    --after-install "postinst" \
    --before-remove "prerm" \
    --name ${PACKAGE_NAME} \
    --package ${OUTPUT_PATH} \
    ${TMP_DIR}

rm -rf ${TMP_DIR}