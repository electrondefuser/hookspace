cmake_minimum_required(VERSION 3.22.1)
project("hookdetector")

add_library(hookdetector SHARED hook_detector.cpp)

find_library(log-lib log)

target_link_libraries(hookdetector ${log-lib})

target_compile_options(hookdetector PRIVATE -std=c++17 -O2)
