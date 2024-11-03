cmake_minimum_required(VERSION 3.21)

project(keyx)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(KEYX_BUILD_TESTS "Build KEYX tests" ON)
option(KEYX_INSTALL "Install keyx's header and library" ON)

include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "."
)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(nlohmann-json_IMPLICIT_CONVERSIONS OFF)

set(LIB_NAME "keyx")
set(keyx_library_HEADERS 
    "include/keyx/license.h"
    "include/keyx/export.h"
	
    "keyx/crypto/base64.h" 
	"keyx/crypto/key.h"
    "keyx/crypto/private_key.h"
    "keyx/crypto/public_key.h"
    "keyx/crypto/rsa.h"
    "keyx/license/license_infomation.h"
    "keyx/global.h"
)

set(keyx_library_SOURCES
    "keyx/crypto/base64.cpp"
    "keyx/crypto/private_key.cpp"
    "keyx/crypto/public_key.cpp"
    "keyx/crypto/rsa.cpp"
    "keyx/license/license.cpp"
)

add_library(${LIB_NAME}
    ${keyx_library_HEADERS}
    ${keyx_library_SOURCES}
)
    
target_link_libraries(${LIB_NAME} PRIVATE
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

if(WIN32)
target_compile_options(${LIB_NAME} PRIVATE /EHsc)
endif()

if (KEYX_BUILD_TESTS)
enable_testing()

find_package(GTest CONFIG REQUIRED)

set(keyx_tests_SOURCES
    "keyx/crypto/base64_test.cpp"
)

set(TEST_TARGET_NAME "keyx_tests")

add_executable(${TEST_TARGET_NAME}
    ${keyx_tests_SOURCES}
)

target_link_libraries(${TEST_TARGET_NAME}
    PRIVATE
    GTest::gtest    
    GTest::gtest_main
    ${LIB_NAME} 
)

include(GoogleTest)
gtest_discover_tests(${TEST_TARGET_NAME})

endif() 


