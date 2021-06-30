cmake_minimum_required(VERSION 3.19)
project(Spoofer)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Spdlog/)

add_executable(${PROJECT_NAME} Src/main.cpp Src/Registry/Registry.cpp Src/Registry/Registry.h Src/pch.h Src/Registry/RegistryValue.cpp Src/Registry/RegistryValue.h Src/Util/Randomizer.cpp Src/Util/Randomizer.h Src/Util/Util.cpp Src/Util/Util.h Src/Registry/RegistryManager.cpp Src/Registry/RegistryManager.h Src/Spoof/Spoof.cpp Src/Spoof/Spoof.h)
target_precompile_headers(${PROJECT_NAME} PRIVATE Src/pch.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Json/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Spdlog/include)

if (MSVC)
    SET_TARGET_PROPERTIES(Spoofer PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE")
    add_definitions(-DMSVC)
endif ()