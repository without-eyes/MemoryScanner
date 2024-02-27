cmake_minimum_required(VERSION 3.27)
project(MemoryScanner C)

set(CMAKE_C_STANDARD 11)

add_executable(MemoryScanner main.c
        testmemscan.c)
