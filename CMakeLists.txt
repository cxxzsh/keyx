cmake_minimum_required(VERSION 3.13)

project(keyx VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#set(CPACK_GENERATOR ZIP)
#set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

#include(CPack)

include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

find_package(OpenSSL REQUIRED)

add_subdirectory(keyx)