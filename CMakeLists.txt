# Copyright (c), CommunityLogiq Software

cmake_minimum_required(VERSION 3.22)

include(cmake/version.cmake)

project("ulsdk" VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH} LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
pkg_check_modules(LIBFLATBUFFERS REQUIRED flatbuffers)
pkg_check_modules(LIBARROW REQUIRED arrow)

file(GLOB_RECURSE sources cpp/src/**/*.cpp cpp/src/*.cpp)
add_library(ulsdk STATIC ${sources})

set_property(TARGET ulsdk PROPERTY CXX_STANDARD 17)

target_include_directories(ulsdk
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cpp/src
        ${LIBCURL_INCLUDE_DIRS}
        ${LIBSODIUM_INCLUDE_DIRS}
        ${LIBFLATBUFFERS_INCLUDE_DIRS}
        ${LIBARROW_INCLUDE_DIRS}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/cpp/include
)

set(public_headers
    cpp/include/ulsdk/ulsdk.h
    cpp/include/ulsdk/keys.h
    cpp/include/ulsdk/request_context.h
    cpp/include/ulsdk/api_key_context.h
)

set_target_properties(ulsdk PROPERTIES PUBLIC_HEADER "${public_headers}")
set_target_properties(ulsdk PROPERTIES DEBUG_POSTFIX "d")

if(MSVC)
    target_compile_options(ulsdk PRIVATE /W4 /WX)
else()
    target_compile_options(ulsdk PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

configure_file(cmake/ulsdk.pc.in ulsdk.pc @ONLY)
install(DIRECTORY cpp/include/ulsdk DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ulsdk.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(TARGETS ulsdk
    EXPORT UlsdkTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

file(GLOB_RECURSE test_sources cpp/test/**/*.cpp cpp/test/*.cpp)
add_executable(testulsdk ${test_sources})
set_property(TARGET testulsdk PROPERTY CXX_STANDARD 17)
target_link_directories(testulsdk
    PRIVATE
        ${LIBCURL_LIBRARY_DIRS}
        ${LIBSODIUM_LIBRARY_DIRS}
        ${LIBFLATBUFFERS_LIBRARY_DIRS}
        ${LIBARROW_LIBRARY_DIRS}
)
target_link_libraries(testulsdk
    PRIVATE
        ulsdk
        ${LIBCURL_LIBRARIES}
        ${LIBSODIUM_LIBRARIES}
        ${LIBFLATBUFFERS_LIBRARIES}
        ${LIBARROW_LIBRARIES}
)
target_include_directories(testulsdk
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cpp/test
        ${LIBCURL_INCLUDE_DIRS}
        ${LIBSODIUM_INCLUDE_DIRS}
        ${LIBFLATBUFFERS_INCLUDE_DIRS}
        ${LIBARROW_INCLUDE_DIRS}
)
