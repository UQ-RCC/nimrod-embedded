#!/bin/bash -e
##
# nimrun build script for RCC's HPC environment
# Run on Tinaroo, Awoonga, or FlashLite
##

export CMAKE=/gpfs1/sw1/RCC/NimrodG/devenv/cmake-3.11.4-Linux-x86_64/bin/cmake
export PROJECT_BASE=${HOME}/staging/nimrod-embedded
export CMAKE_TOOLCHAIN_FILE=${PROJECT_BASE}/cmake-toolchain-rcc.cmake
export CMAKE_BINARY_DIR=${PROJECT_BASE}/build-rcc

mkdir -p ${CMAKE_BINARY_DIR}
pushd ${CMAKE_BINARY_DIR}
	${CMAKE} \
		-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
		-DCMAKE_BUILD_TYPE=MinSizeRel \
		${PROJECT_BASE}/nimrun
	make -j nimrun
	strip -s nimrun
popd
