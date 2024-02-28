cmake_minimum_required(VERSION 3.25)

project(ghc16 CXX)
set(CMAKE_CXX_STANDARD 23)

include(cmake/CheckAVX.cmake)
Check_for_AVX()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This project is designed to only support a 64-bit build!")
endif()
if (NOT MSVC)
    message(FATAL_ERROR "The only supported compiler for the project is MSVC")
endif()

if (MSVC)
    # 4201: non-standard extension nameless struct
    # GR-: disable RTTI
    add_compile_options(/W4 /fp:fast /wd4201 /GR- /Oi ${AVX_FLAGS})
    add_compile_definitions(VC_EXTRALEAN)
    #add_link_options(/SUBSYSTEM:windows /ENTRY:mainCRTStartup)
    if(CMAKE_BUILD_TYPE EQUAL Release)
        add_compile_options(/MT /O2)
    endif()
    if(CMAKE_BUILD_TYPE EQUAL Debug)
        add_compile_options(/MTd /fsanitize=address)
    endif()
endif ()

add_subdirectory(src)