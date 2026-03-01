cmake_minimum_required(VERSION 3.20)

project(CloudflareDDNS VERSION 0.0.0 LANGUAGES CXX)

set(CloudflareDDNS_MAIN_PROJECT OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(CloudflareDDNS_MAIN_PROJECT ON)
endif()

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

option(USE_CPPHTTPLIB "Use cpp-httplib as the HTTP client library" ON)
option(USE_SWSCLIB "Use swsclib as the HTTP client library" OFF)

if (${USE_CPPHTTPLIB} AND ${USE_SWSCLIB})
    message(FATAL_ERROR "Cannot use both cpp-httplib and swsclib at the same time")
elseif (NOT ${USE_CPPHTTPLIB} AND NOT ${USE_SWSCLIB})
    message(FATAL_ERROR "Must use either cpp-httplib or swsclib as the HTTP client library")
elseif (${USE_CPPHTTPLIB})
    add_definitions(-DUSE_CPPHTTPLIB)
    message(STATUS "Using cpp-httplib as the HTTP client library")
elseif (${USE_SWSCLIB})
    add_definitions(-DUSE_SWSCLIB)
    add_definitions(-DASIO_STANDALONE)
    message(STATUS "Using swsclib as the HTTP client library")
endif()

add_subdirectory(external)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/include)

add_subdirectory(src)
