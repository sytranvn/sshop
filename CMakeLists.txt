cmake_minimum_required(VERSION 3.13) # CMake version check

# Specify search path for CMake modules to be loaded by include()
# and find_package()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

project(sshop) # Create project

# Add defaults for cmake
# Those need to be set before the project() call.
include(DefineCMakeDefaults)
include(DefineCompilerFlags)


# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")


set(CLIENT_EXE "${PROJECT_NAME}-client")
set(SERVER_EXE "${PROJECT_NAME}-server")
# add_subdirectory(lib)
# include_directories(lib)

include(FindPkgConfig)
pkg_check_modules(LIBSSH REQUIRED libssh)
include_directories(${LIBSSH_INCLUDE_DIRS})
link_directories(${LIBSSH_LIBRARY_DIRS})
# Add executable target with source files listed in SOURCE_FILES variable
add_executable(${CLIENT_EXE} client.c)
target_link_libraries(${CLIENT_EXE} ${LIBSSH_LIBRARIES})

add_executable(${SERVER_EXE} server.c)
target_link_libraries(${SERVER_EXE} ${LIBSSH_LIBRARIES})

if (UNIT_TESTING)
	include_directories(tests)
endif(UNIT_TESTING)


message(STATUS "********************************************")
message(STATUS "********** ${PROJECT_NAME} build options : **********")
message(STATUS "Unit testing: ${UNIT_TESTING}")

message(STATUS "********************************************")


