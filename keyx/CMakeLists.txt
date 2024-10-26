string(TOLOWER ${PROJECT_NAME} LOWER_STRING)

set(TARGET_NAME ${LOWER_STRING})

set(keyx_library_HEADERS
    "crypto/private_key.h"
    "crypto/public_key.h"
    "crypto/rsa.h"
    "license/license.h"
    "signature/signature.h"
    "global.h"
    "key.h"
 "crypto/base64.h")

set(keyx_library_SRCS
    "crypto/private_key.cpp"
    "crypto/public_key.cpp"
    "crypto/rsa.cpp"
    "license/license.cpp"
    "signature/signature.cpp"
    "main.cpp"
 "crypto/base64.cpp")

add_executable(${TARGET_NAME})

target_sources(${TARGET_NAME} PRIVATE ${keyx_library_HEADERS} ${keyx_library_SRCS})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/keyx)
target_link_libraries(${TARGET_NAME} PRIVATE
    nlohmann_json::nlohmann_json
    OpenSSL::SSL 
    OpenSSL::Crypto
)

