include(AddSubModule)

add_submodule(platform-specific)

add_submodule(cJSON
    DEPENDS platform-specific)
add_submodule(zlib
    DEPENDS platform-specific)
add_submodule(libressl
    DEPENDS platform-specific)
add_submodule(curl
    DIRECTORY libcurl
    DEPENDS platform-specific libressl zlib)

if(WIN32)
    add_submodule(PDCurses
        DEPENDS platform-specific)
endif()
