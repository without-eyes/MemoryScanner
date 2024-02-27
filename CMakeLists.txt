cmake_minimum_required(VERSION 3.27)
project(MemoryScanner C)

set(CMAKE_C_STANDARD 11)

set(PROGRAM_NAME MemoryScanner)

add_executable(${PROGRAM_NAME} src/core/main.c
        src/ui/UserInterface.c
        include/memscan/ui/UserInterface.h
        src/core/CoreFunctions.c
        include/memscan/core/CoreFunctions.h
)

target_include_directories(
        ${PROGRAM_NAME}
        PRIVATE
        include
)

add_subdirectory(src/ui)
add_subdirectory(include/memscan/ui)
add_subdirectory(src/core)
add_subdirectory(include/memscan/core)

project(UI_Project)
add_library(UI SHARED UserInterface.c UserInterface.h)

project(Core_Project)
# Create a shared library for LibB as well.
add_library(Core SHARED CoreFunctions.c CoreFunctions.h main.c)

# Link LibA to LibB as a dependency.
target_link_libraries(UI Core)
