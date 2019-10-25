#!/bin/bash -e
##
# nimrun build script for RCC's HPC environment
# Run on Tinaroo, Awoonga, or FlashLite
##

export CMAKE=/gpfs1/sw1/RCC/NimrodG/devenv/cmake-3.11.4-Linux-x86_64/bin/cmake
export PROJECT_BASE=${HOME}/staging/nimrod-embedded
export CMAKE_BINARY_DIR=${PROJECT_BASE}/build-rcc

module load gnu/7.2.0

mkdir -p ${CMAKE_BINARY_DIR}
pushd ${CMAKE_BINARY_DIR}
	${CMAKE} \
		-DCMAKE_C_COMPILER=gcc \
		-DCMAKE_CXX_COMPILER=g++ \
		-DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++" \
		-DCMAKE_BUILD_TYPE=MinSizeRel \
		${PROJECT_BASE}/nimrun
	make -j nimrun
	strip -s nimrun
popd
