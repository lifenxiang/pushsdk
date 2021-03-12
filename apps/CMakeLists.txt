include(AddSubModule)

set(DEPEND_MODULES
    push0)

if(WIN32)
    set(DEPEND_MODULES
        ${DEPEND_MODULES}
        PDCurses
        libcrystal)
endif()

add_submodule(pushshell
    DIRECTORY shell
    DEPENDS ${DEPEND_MODULES})

add_submodule(pushtool
    DIRECTORY tool
    DEPENDS ${DEPEND_MODULES})
