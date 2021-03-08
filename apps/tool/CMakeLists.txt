project(carrier-shell C)

include(CarrierDefaults)
include(CheckIncludeFile)
include(CheckFunctionExists)

set(SRC
    tool.c)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(SYSTEM_LIBS pthread)
endif()

include_directories(
    ../../src
    ${CARRIER_INT_DIST_DIR}/include)

link_directories(
    ${CARRIER_INT_DIST_DIR}/lib
    ${CMAKE_CURRENT_BINARY_DIR}/../../src)

set(LIBS
    push)

if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")
    set(LIBS
        ${LIBS}
        Shlwapi)
else()
    set(LIBS
        ${LIBS})
endif()

add_executable(pushtool ${SRC})

target_link_libraries(pushtool ${LIBS} ${SYSTEM_LIBS})

install(TARGETS pushtool
    RUNTIME DESTINATION "bin"
    ARCHIVE DESTINATION "lib"
    LIBRARY DESTINATION "lib")
