cmake_minimum_required(VERSION 3.0)

project(janus-signalling-proxy)

option(BUILD_AGENT "Enable build Agent application" ON)
option(BUILD_PROXY "Enable build Proxy application" ON)
option(BUILD_TEST "Enable build Test application" OFF)

if(DEFINED ENV{SNAPCRAFT_BUILD_ENVIRONMENT})
    add_definitions(-DSNAPCRAFT_BUILD=1)
    set(SNAPCRAFT_BUILD YES)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    add_definitions(-Wall)
endif(CMAKE_COMPILER_IS_GNUCC)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(DEPS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DEPS_DIR}
    )

add_subdirectory(deps/CxxPtr)
add_subdirectory(Common)

if(BUILD_AGENT)
    add_subdirectory(Agent)
    add_subdirectory(AgentApp)
endif(BUILD_AGENT)

if(BUILD_PROXY)
    add_subdirectory(Proxy)
    add_subdirectory(ProxyApp)
endif(BUILD_PROXY)

if(BUILD_TEST)
    add_subdirectory(Test)
endif(BUILD_TEST)
