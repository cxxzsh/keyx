cmake_minimum_required(VERSION 3.13)
project(YourProject CXX)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
include(FetchContent)

# Import Tink as an in-tree dependency.
FetchContent_Declare(
  tink
  URL       https://github.com/tink-crypto/tink-cc/archive/refs/tags/v2.2.0.zip
  URL_HASH  SHA256=88e1442182452caa16d0954ceaf73e17b0aa30837ee6c0cc16bf0112313ce753
)
FetchContent_GetProperties(tink)
if(NOT googletest_POPULATED)
  FetchContent_Populate(tink)
    add_subdirectory(${tink_SOURCE_DIR} ${tink_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

add_subdirectory(src)