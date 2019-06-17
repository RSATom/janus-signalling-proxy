cmake_minimum_required(VERSION 3.0)

project(Proxy)

find_package(PkgConfig REQUIRED)
pkg_search_module(WS REQUIRED libwebsockets)
pkg_search_module(JANSSON REQUIRED jansson)
pkg_search_module(LIBCONFIG REQUIRED libconfig)

find_package(OpenSSL REQUIRED)

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    [^.]*.cpp
    [^.]*.h
    [^.]*.cmake
    )

add_library(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC
    ${LIBCONFIG_INCLUDE_DIRS}
    ${WS_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
    ${LIBCONFIG_LIBRARIES}
    ${WS_LIBRARIES}
    ${JANSSON_LIBRARIES}
    Common)
