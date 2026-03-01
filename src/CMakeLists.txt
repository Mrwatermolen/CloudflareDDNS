add_executable(my_ddns
    main.cpp
    cloudflare_ddns.cpp
    miwifi.cpp
)

target_link_libraries(my_ddns PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_include_directories(my_ddns PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(my_ddns PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)

add_executable(test_client
    test.cpp
)

target_link_libraries(test_client PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_include_directories(test_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)