cmake_minimum_required(VERSION 3.16)

project(ElGamalPKE VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "Disable Crypto++ self tests" FORCE)
set(CRYPTOPP_BUILD_DOCUMENTATION OFF CACHE BOOL "Disable Crypto++ documentation" FORCE)
set(CRYPTOPP_BUILD_SHARED OFF CACHE BOOL "Build Crypto++ as a shared library" FORCE)

FetchContent_Declare(cryptopp_cmake
    GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
    GIT_TAG CRYPTOPP_8_9_0
)

FetchContent_MakeAvailable(cryptopp_cmake)

FetchContent_GetProperties(cryptopp_cmake)
if(NOT cryptopp_cmake_POPULATED)
    message(FATAL_ERROR "cryptopp-cmake content is not available")
endif()

set(CRYPTOPP_INCLUDE_DIR "${cryptopp_cmake_SOURCE_DIR}/cryptopp" CACHE PATH "Crypto++ include dir" FORCE)

add_executable(elgamal
    el_gamal_pke.cpp
    el_gamal_pke.h
    Euclidean.h
)

target_include_directories(elgamal PRIVATE ${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(elgamal PRIVATE cryptopp)
