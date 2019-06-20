cmake_minimum_required(VERSION 3.0)

project(ProxyApp)

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    [^.]*.cpp
    [^.]*.h
    [^.]*.cmake
    [^.]*.conf
    )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME}
    Proxy)

install(TARGETS ProxyApp DESTINATION bin)
