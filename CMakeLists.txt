cmake_minimum_required(VERSION 3.20)
project(basic VERSION 0.1.0 LANGUAGES C CXX)

file(GLOB src
     "*.hpp"
     "*.cpp"
)

add_library(basic SHARED ${src})

set_property(TARGET basic PROPERTY CXX_STANDARD 17) # C++17