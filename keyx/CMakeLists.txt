string(TOLOWER ${PROJECT_NAME} LOWER_STRING)

set(TARGET_NAME ${LOWER_STRING})

add_executable(${TARGET_NAME} 
                main.cpp
)
target_link_libraries(keyx PRIVATE
    #tink::static
    nlohmann_json::nlohmann_json
    OpenSSL::SSL 
    OpenSSL::Crypto
)
