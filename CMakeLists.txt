cmake_minimum_required(VERSION 3.15)

project(picozstd VERSION 0.1.0 LANGUAGES C)

add_library(picozstd STATIC picozstd.c)
target_include_directories(picozstd PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(picozstd PUBLIC c_std_11)
set_target_properties(picozstd PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(MSVC)
    target_compile_options(picozstd PRIVATE /W4)
else()
    target_compile_options(picozstd PRIVATE -Wall -Wextra -Wpedantic)
endif()

set(PICOCOMPRESS_INCLUDE_DIR "" CACHE PATH "Path containing picocompress/codec.h")
option(PICOZSTD_BUILD_PICOCOMPRESS_CODEC "Build the PicoCompress codec module when headers are available" ON)

if(PICOZSTD_BUILD_PICOCOMPRESS_CODEC)
    if(NOT PICOCOMPRESS_INCLUDE_DIR)
        find_path(PICOCOMPRESS_INCLUDE_DIR picocompress/codec.h)
    endif()
    if(PICOCOMPRESS_INCLUDE_DIR)
        add_library(picocodec_zstd SHARED picocompress_codec.c)
        target_include_directories(picocodec_zstd PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${PICOCOMPRESS_INCLUDE_DIR}"
        )
        target_compile_features(picocodec_zstd PRIVATE c_std_11)
        target_link_libraries(picocodec_zstd PRIVATE picozstd)
        if(MSVC)
            target_compile_options(picocodec_zstd PRIVATE /W4)
        else()
            target_compile_options(picocodec_zstd PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    else()
        message(STATUS "PicoCompress headers not found; picocodec_zstd module skipped")
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(picozstd_tests tests/test_picozstd.c)
    target_link_libraries(picozstd_tests PRIVATE picozstd)
    target_compile_features(picozstd_tests PRIVATE c_std_11)
    if(MSVC)
        target_compile_options(picozstd_tests PRIVATE /W4)
    else()
        target_compile_options(picozstd_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME picozstd_tests COMMAND picozstd_tests)

    if(PICOCOMPRESS_INCLUDE_DIR)
        add_executable(picozstd_picocompress_tests
            tests/test_picocompress_codec.c
            picocompress_codec.c
        )
        target_compile_definitions(picozstd_picocompress_tests PRIVATE PCX_CODEC_STATIC=1)
        target_include_directories(picozstd_picocompress_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${PICOCOMPRESS_INCLUDE_DIR}"
        )
        target_compile_features(picozstd_picocompress_tests PRIVATE c_std_11)
        target_link_libraries(picozstd_picocompress_tests PRIVATE picozstd)
        if(MSVC)
            target_compile_options(picozstd_picocompress_tests PRIVATE /W4)
        else()
            target_compile_options(picozstd_picocompress_tests PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME picozstd_picocompress_tests COMMAND picozstd_picocompress_tests)
    endif()
endif()
