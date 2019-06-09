cmake_minimum_required(VERSION 3.0)

project(Proxy)

find_package(PkgConfig REQUIRED)
pkg_search_module(WS REQUIRED libwebsockets)
pkg_search_module(JANSSON REQUIRED jansson)

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    [^.]*.cpp
    [^.]*.h
    [^.]*.cmake
    )

add_library(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME}
    ${WS_LIBRARIES}
    ${JANSSON_LIBRARIES})
