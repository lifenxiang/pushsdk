project(libcrystal)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
        libcrystal

        PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
        URL "https://github.com/iwhisperio/libcrystal/archive/release-v1.0.7.tar.gz"
        URL_HASH SHA256=c0f04f0642d92d76839bb4f11bdd24f0b9a7f962b7b8d1ae06c9a06a484f412f
        DOWNLOAD_NAME "libcrystal-release-v1.0.7.tar.gz"
        DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DENABLE_STATIC=TRUE
        -DENABLE_SHARED=FALSE
        -DLIBSODIUM_STATIC=FALSE
        -DENABLE_CRYPTO=FALSE
        -DENABLE_TESTS=FALSE
        ${CMAKE_ARGS_INIT}
)
