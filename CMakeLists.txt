cmake_minimum_required(VERSION 3.19)
project(Spoofer)

set(CMAKE_CXX_STANDARD 20)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

#Checks build type and adds a define
add_definitions(-DEmberBuild_${CMAKE_BUILD_TYPE})
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Spdlog/)
add_executable(${PROJECT_NAME} Src/main.cpp Src/Registry/Registry.cpp
        Src/Registry/Registry.h
        Src/pch.h
        Src/Registry/RegistryValue.cpp Src/Registry/RegistryValue.h Src/Util/Randomizer.cpp Src/Util/Randomizer.h Src/Util/Util.cpp Src/Util/Util.h Src/Registry/RegistryManager.cpp Src/Registry/RegistryManager.h Src/Spoof/Spoof.cpp Src/Spoof/Spoof.h Src/Util/Logger.hpp)
target_precompile_headers(${PROJECT_NAME} PRIVATE Src/pch.h)

set(INCLUDE_DIRECTORIES PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Json/
        ${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Spdlog/include
        )
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRECTORIES})

if (MSVC)
    SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator'
    uiAccess='false'\" /SUBSYSTEM:CONSOLE")
    add_definitions(-DMSVC)
endif ()