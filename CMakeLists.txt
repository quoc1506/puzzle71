cmake_minimum_required(VERSION 3.14)
project(puzzle71_solver CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-O3 -funroll-loops -pthread)
    # Enable native optimizations if supported
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
    if(COMPILER_SUPPORTS_MARCH_NATIVE)
        add_compile_options(-march=native)
    endif()
endif()

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(puzzle71_solver puzzle71_solver.cpp)

target_link_libraries(puzzle71_solver
    PRIVATE
    CURL::libcurl
    OpenSSL::Crypto
    OpenSSL::SSL
    secp256k1
    Threads::Threads
)
