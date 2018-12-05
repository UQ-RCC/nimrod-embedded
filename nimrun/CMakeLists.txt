cmake_minimum_required(VERSION 3.3)
project(nimrun)

enable_language(C CXX)

find_package(Threads REQUIRED)
find_package(OpenSSL 1.0.1 REQUIRED) # Needed by PBS
find_library(PBS_LIBRARIES pbs /opt/pbs/lib /opt/pbspro-14.1.0/lib)

if(NOT PBS_LIBRARIES)
	message(FATAL_ERROR "Can't find PBS")
else()
	message(STATUS "Found PBS at ${PBS_LIBRARIES}")
endif()

get_filename_component(PBS_ROOT ${PBS_LIBRARIES} DIRECTORY)
set(PBS_ROOT ${PBS_ROOT}/../)
get_filename_component(PBS_ROOT ${PBS_ROOT} ABSOLUTE)
message(STATUS "PBS installed at ${PBS_ROOT}")

execute_process(
	COMMAND git describe --tags --always
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	OUTPUT_VARIABLE NIMRUN_GITVERSION
	RESULT_VARIABLE GIT_STATUS
	OUTPUT_STRIP_TRAILING_WHITESPACE
	ERROR_STRIP_TRAILING_WHITESPACE
)

set(NIMRUN_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include" )
configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${NIMRUN_GENERATED_INCLUDE_DIR}/config.h")

if(NOT GIT_STATUS EQUAL 0)
	message(WARNING "Failed to retrieve git info, status: ${GIT_STATUS}")
endif()

add_executable(nimrun
	nimrun.cpp
	ip.cpp
	ssl.cpp
	pbs.cpp
	qpid.cpp
	nimrun.hpp
	json.hpp
	args.cpp
	nimrod.cpp
	utils.cpp

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

target_include_directories(nimrun PRIVATE "${PBS_ROOT}/include")
target_link_libraries(nimrun ${PBS_LIBRARIES})

target_include_directories(nimrun PRIVATE "${NIMRUN_GENERATED_INCLUDE_DIR}")

target_compile_definitions(nimrun PRIVATE __STDC_LIMIT_MACROS)

