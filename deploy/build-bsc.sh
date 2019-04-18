#!/bin/bash -e
##
# nimrun build script for BSC
# Run on DEMORGOGON
##

export CMAKE=cmake
export PROJECT_BASE=${HOME}/rcchome/staging/nimrod-embedded
export CMAKE_TOOLCHAIN_FILE=${HOME}/Documents/Coding/nimrodg-agent/cibuild/x86_64-pc-linux-musl.cmake
export CMAKE_BINARY_DIR=${PROJECT_BASE}/build-bsc

# We piggyback off the agent's build environment so I don't need
# to rebuild LibreSSL
export CMAKE_INSTALL_PREFIX=${HOME}/Desktop/abuild-musl/prefix
export PKG_CONFIG_PATH=${CMAKE_INSTALL_PREFIX}/lib/pkgconfig

mkdir -p ${CMAKE_BINARY_DIR}
pushd ${CMAKE_BINARY_DIR}
	${CMAKE} \
		-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
		-DCMAKE_BUILD_TYPE=MinSizeRel \
		-DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} \
		${PROJECT_BASE}/nimrun
	make -j nimrun
	strip -s nimrun
popd
