project(cJSON)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    cJSON

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/DaveGamble/cJSON/archive/v1.7.14.tar.gz"
    URL_HASH SHA256=fb50a663eefdc76bafa80c82bc045af13b1363e8f45cec8b442007aef6a41343
    DOWNLOAD_NAME "cJSON-1.7.14.tar.gz"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DBUILD_SHARED_LIBS=Off
        -DENABLE_CJSON_TEST=Off
        -DENABLE_HIDDEN_SYMBOLS=On
        ${CMAKE_ARGS_INIT}
)

if(ENABLE_STATIC)
    export_static_library(cjson)
endif()
