set(CMAKE_SYSTEM_NAME Linux)

set(tuple x86_64-centos7-linux-gnu)
set(tools /gpfs1/sw7/RCC/NimrodG/devenv/${tuple})

set(CMAKE_C_COMPILER ${tools}/bin/${tuple}-gcc)
set(CMAKE_CXX_COMPILER ${tools}/bin/${tuple}-g++)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libstdc++ -mindirect-branch=thunk -I/usr/include" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++ -mindirect-branch=thunk -I/usr/include" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -Wl,-rpath-link,/lib64" CACHE STRING "" FORCE)
