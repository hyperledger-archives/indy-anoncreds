#!/usr/bin/env bash

set -e
set -x

OUTPUT_PATH=${1:-.}

function build_from_pypi {
    PACKAGE_NAME=$1

    if [ ${PACKAGE_NAME} == "Charm-Crypto" ];
    then
        EXTRA_DEPENDENCE="-d libpbc0"
    else
        EXTRA_DEPENDENCE=""
    fi

    if [ -z $2 ]; then
        PACKAGE_VERSION=""
    else
        PACKAGE_VERSION="==$2"
    fi
    POSTINST_TMP=postinst-${PACKAGE_NAME}
    PREREM_TMP=prerm-${PACKAGE_NAME}
    cp postinst ${POSTINST_TMP}
    cp prerm ${PREREM_TMP}
    sed -i 's/{package_name}/python3-'${PACKAGE_NAME}'/' ${POSTINST_TMP}
    sed -i 's/{package_name}/python3-'${PACKAGE_NAME}'/' ${PREREM_TMP}

    fpm --input-type "python" \
        --output-type "deb" \
        --architecture "amd64" \
        --verbose \
        --python-package-name-prefix "python3"\
        --python-bin "/usr/bin/python3" \
        --exclude "*.pyc" \
        --exclude "*.pyo" \
        ${EXTRA_DEPENDENCE} \
        --maintainer "Hyperledger <hyperledger-indy@lists.hyperledger.org>" \
        --after-install ${POSTINST_TMP} \
        --before-remove ${PREREM_TMP} \
        --package ${OUTPUT_PATH} \
        ${PACKAGE_NAME}${PACKAGE_VERSION}

    rm ${POSTINST_TMP}
    rm ${PREREM_TMP}
}

function build_and_install_pbc {
    VERSION=$1
    # build pbc
    TEM_DIR="$(mktemp -d)"
    pushd ${TEM_DIR}
    git clone http://repo.or.cz/r/pbc.git
    pushd pbc
    git checkout 656ae0c90e120eacd3dc0d76dbc9504f8aca4ba8
    dpkg-buildpackage -uc -us

    popd
    dirs -v

    # install pbc
    LIB_PBC_DEB=libpbc0_${VERSION}_amd64.deb
    LIB_PBC_DEV_DEB=libpbc-dev_${VERSION}_amd64.deb
    if [ -f /.dockerenv ]; then
        # inside a docker container
        dpkg -i ${LIB_PBC_DEB}
        dpkg -i ${LIB_PBC_DEV_DEB}
    else
        # a regular system
        sudo dpkg -i ${LIB_PBC_DEB}
        sudo dpkg -i ${LIB_PBC_DEV_DEB}
    fi

    # copy deb packages into OUTPUT_PATH
    cp ${LIB_PBC_DEB} ${OUTPUT_PATH}
    cp ${LIB_PBC_DEV_DEB} ${OUTPUT_PATH}

    # cleanup
    popd
    rm -rf ${TEM_DIR}

}

build_from_pypi base58

# has to happen before building `Charm-Crypto`
build_and_install_pbc 0.5.14

build_from_pypi Charm-Crypto

