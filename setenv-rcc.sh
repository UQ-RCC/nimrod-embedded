#1/bin/sh
set -x

if [ -z "${HOSTNAME}" ]; then
	HOSTNAME=$(hostname)
fi

if [ ${HOSTNAME} = "wiener.hpc.dc.uq.edu.au" ]; then
	module load cmake/3.12.2 gnu7/7.3.0
	export CC=gcc
	export CXX=g++
elif [ ${HOSTNAME} = "tinaroo1.local" ] || [ ${HOSTNAME} = "tinaroo2.local" ] || [ ${HOSTNAME} = "flashlite1.local" ] || [ ${HOSTNAME} = "flashlite2.local" ]; then
	export PATH="/sw/RCC/NimrodG/devenv/cmake-3.11.4-Linux-x86_64/bin:${PATH}"
	#export CC="/gpfs1/sw7/RCC/NimrodG/devenv/x86_64-centos7-linux-gnu/bin/x86_64-centos7-linux-gnu-gcc"
	#export CXX="/gpfs1/sw7/RCC/NimrodG/devenv/x86_64-centos7-linux-gnu/bin/x86_64-centos7-linux-gnu-g++"
	#export CFLAGS="-I/usr/include"
	#export CXXFLAGS="-I/usr/include"
	#export LDFLAGS="-static-libstdc++ -Wl,-rpath-link,/lib64"
	module load gnu/7.2.0
	export CC=gcc
	export CXX=g++
	export LDFLAGS="-static-libstdc++"
fi
