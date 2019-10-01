cmake_minimum_required(VERSION 3.10)
project(nimrun)

enable_language(C CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(GetGitRevisionDescription)

find_package(Threads REQUIRED)
find_package(OpenSSL 1.0.1 REQUIRED)

get_git_head_revision(GIT_REFSPEC GIT_SHA1)
git_describe(GIT_DESCRIBE)
git_local_changes(GIT_LOCAL_CHANGES)

if(GIT_DESCRIBE MATCHES "-NOTFOUND$")
	set(GIT_DESCRIBE "UNKNOWN")
endif()

if(GIT_LOCAL_CHANGES MATCHES "DIRTY")
	set(GIT_DESCRIBE "${GIT_DESCRIBE}-${GIT_LOCAL_CHANGES}")
	set(GIT_DIRTY "true")
else()
	set(GIT_DIRTY "false")
endif()

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")
configure_file("${PROJECT_SOURCE_DIR}/config.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/config.cpp")

add_executable(nimrun
	"${CMAKE_CURRENT_BINARY_DIR}/config.h"
	"${CMAKE_CURRENT_BINARY_DIR}/config.cpp"

	nimrun.cpp
	ip.cpp
	ssl.cpp

	detect.cpp

	rcc.cpp
	minipbs.hpp
	minipbs.cpp

	wiener.cpp

	bsc.cpp

	qpid.cpp
	nimrun.hpp
	json.hpp
	args.cpp
	nimrod.cpp
	utils.cpp

	shell.cpp

	parg.c
	parg.h
)

set_property(TARGET nimrun PROPERTY C_STANDARD 11)
set_property(TARGET nimrun PROPERTY CXX_STANDARD 17)
set_property(TARGET nimrun PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(nimrun Threads::Threads)
target_link_libraries(nimrun OpenSSL::Crypto)
target_link_libraries(nimrun OpenSSL::SSL)

target_link_libraries(nimrun stdc++fs)
target_link_libraries(nimrun dl)

target_include_directories(nimrun PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

target_compile_definitions(nimrun PRIVATE __STDC_LIMIT_MACROS)

