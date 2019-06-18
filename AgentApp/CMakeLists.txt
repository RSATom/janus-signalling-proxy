cmake_minimum_required(VERSION 3.0)

project(AgentApp)

file(GLOB SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    [^.]*.cpp
    [^.]*.h
    [^.]*.cmake
    )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME}
    Agent)

install(TARGETS AgentApp DESTINATION bin)
