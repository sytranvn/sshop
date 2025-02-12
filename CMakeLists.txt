cmake_minimum_required(VERSION 3.13) # CMake version check
project(project) # Create project
set(CMAKE_C_STANDARD 23) # Enable c23
set(CMAKE_CXX_STANDARD 17) # Enable cpp17
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# add_subdirectory(lib)
# include_directories(lib)

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(main main.c)

# include_directories(tests)
