cmake_minimum_required(VERSION 3.10)
project(wmbus-decrypter CXX C)

# Define source files for the main application and the AES library
set(SOURCE_FILES
    main.cpp
    aes-lib/aes.c
)

# Create the executable target
add_executable(wmbus-decrypter ${SOURCE_FILES})

# Compiler flags for clean and optimized build
target_compile_options(wmbus-decrypter PRIVATE -Wall -Wextra -O3 -std=c++17)

# Set the include directory for the AES library
target_include_directories(wmbus-decrypter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/aes-lib)