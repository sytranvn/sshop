cmake_minimum_required(VERSION 3.13) # CMake version check
project(sshop) # Create project
set(CMAKE_C_STANDARD 23) # Enable c23
set(CMAKE_CXX_STANDARD 17) # Enable cpp17
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CLIENT_EXE "${PROJECT_NAME}-client")
# add_subdirectory(lib)
# include_directories(lib)

include(FindPkgConfig)
pkg_check_modules(LIBSSH REQUIRED libssh)
include_directories(${LIBSSH_INCLUDE_DIRS})
link_directories(${LIBSSH_LIBRARY_DIRS})
# Add executable target with source files listed in SOURCE_FILES variable
add_executable(${CLIENT_EXE} client.c)
target_link_libraries(${CLIENT_EXE} ${LIBSSH_LIBRARIES})

# include_directories(tests)
