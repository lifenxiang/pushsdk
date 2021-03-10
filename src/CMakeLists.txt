project(elastos-carrier C)
cmake_policy(SET CMP0054 NEW)

include(CarrierDefaults)
include(CheckIncludeFile)

set(SRC
    http_client.c
    push.c)

set(HEADERS
    push.h)

include_directories(
    ${CARRIER_INT_DIST_DIR}/include)

link_directories(
    ${CARRIER_INT_DIST_DIR}/lib)

if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")
endif()

set(LIBS
    libcurl
    cjson)

add_definitions(-DCARRIER_BUILD)

add_custom_target(push0)

if(ENABLE_STATIC)
    add_library(push-static STATIC ${SRC})
    add_dependencies(push-static curl cJSON)

    target_compile_definitions(push-static PRIVATE CARRIER_STATIC)
    set_target_properties(push-static PROPERTIES OUTPUT_NAME push)

    add_dependencies(push0 push-static)

    install(TARGETS push-static
            RUNTIME DESTINATION "bin"
            ARCHIVE DESTINATION "lib"
            LIBRARY DESTINATION "lib")
endif()

if(ENABLE_SHARED)
    add_library(push-shared SHARED ${SRC})
    add_dependencies(push-shared curl cJSON)

    target_compile_definitions(push-shared PRIVATE CARRIER_DYNAMIC)
    set_target_properties(push-shared PROPERTIES OUTPUT_NAME push)
    target_link_libraries(push-shared ${LIBS})

    add_dependencies(push0 push-shared)

    install(TARGETS push-shared
            RUNTIME DESTINATION "bin"
            ARCHIVE DESTINATION "lib"
            LIBRARY DESTINATION "lib")
endif()

install(FILES ${HEADERS} DESTINATION "include")