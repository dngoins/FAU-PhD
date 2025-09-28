cmake_minimum_required(VERSION 3.15)

project(AESDemo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(AES
    AES.cpp
)

target_include_directories(AES
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

if(MSVC)
    target_compile_options(AES PRIVATE /W4 /permissive-)
else()
    target_compile_options(AES PRIVATE -Wall -Wextra -pedantic)
endif()
