cmake_minimum_required(VERSION 3.5)
cmake_policy(VERSION 3.5)
project(push-sdk)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(CarrierDefaults)
include(CarrierPackages)
include(AddSubModule)

if(IOS)
    set(ENABLE_SHARED_DEFAULT FALSE)
    set(ENABLE_STATIC_DEFAULT TRUE)
else()
    set(ENABLE_SHARED_DEFAULT TRUE)
    set(ENABLE_STATIC_DEFAULT TRUE)
endif()

if(CMAKE_CROSSCOMPILING)
    set(ENABLE_APPS_DEFAULT FALSE)
else()
    set(ENABLE_APPS_DEFAULT TRUE)
endif()

set(ENABLE_SHARED ${ENABLE_SHARED_DEFAULT} CACHE BOOL "Build shared library")
set(ENABLE_STATIC ${ENABLE_STATIC_DEFAULT} CACHE BOOL "Build static library")
set(ENABLE_APPS ${ENABLE_APPS_DEFAULT} CACHE BOOL "Build demo applications")

add_subdirectory(deps)
add_subdirectory(src)

if(ENABLE_APPS)
    add_subdirectory(apps)
endif()