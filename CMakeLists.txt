cmake_minimum_required(VERSION 3.10)
project(debugger)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Recursively find all .c files
file(GLOB_RECURSE SOURCES "src/*.c")

# Recursively find all .h files for includes
file(GLOB_RECURSE HEADERS "src/*.h")

# Create executable
add_executable(debugger ${SOURCES})

# Include directories
target_include_directories(debugger PRIVATE src/)

# Optional: Add debug symbols
target_compile_options(debugger PRIVATE -g)

# Optional: Add warnings
target_compile_options(debugger PRIVATE -Wall -Wextra)
