cmake_minimum_required(VERSION 3.30)
project(hermes)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (WIN32)
    option(BUILD_STATIC_LIBS "Build the static library" ON)
    option(BUILD_SHARED_LIBS "Build the shared library" OFF)
else ()
    option(BUILD_STATIC_LIBS "Build the static library" ON)
    option(BUILD_SHARED_LIBS "Build the shared library" ON)
endif ()

set(CMAKE_BINARY_DIR ${CMAKE_BINARY_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

find_package(gRPC CONFIG REQUIRED)
find_package(mongocxx REQUIRED CONFIG)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Cryptopp REQUIRED IMPORTED_TARGET libcryptopp)

get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${gRPC_INCLUDE_DIRS})
include_directories(${Cryptopp_INCLUDE_DIRS})
include_directories(${mongocxx_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories("${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/shuffle/include")

add_executable(hermes-server src/main.cpp src/chat_service.cpp include/chat_service.hpp src/protobuf/messages.proto src/protobuf/services.proto
        src/Args.cpp
        src/Args.hpp)
protobuf_generate(TARGET hermes-server LANGUAGE cpp)
protobuf_generate(TARGET hermes-server LANGUAGE grpc GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc PLUGIN "protoc-gen-grpc=${grpc_cpp_plugin_location}")
target_link_libraries(hermes-server protobuf::libprotobuf gRPC::grpc gRPC::grpc++ absl::log_internal_check_op PkgConfig::Cryptopp mongo::mongocxx_shared)
