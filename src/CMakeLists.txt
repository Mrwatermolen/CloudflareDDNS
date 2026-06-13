add_library(telnet_client
    telnet/telnet_client.cpp
)

target_link_libraries(telnet_client PUBLIC
    swsc
)

target_include_directories(telnet_client PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(telnet_example
    telnet/example_telnet_client.cpp
)

target_link_libraries(telnet_example PRIVATE
    telnet_client
)

add_executable(unionman_telnet_login
    unionman_telnet_login.cpp
)

target_link_libraries(unionman_telnet_login PRIVATE
    telnet_client
    swsc
)

target_include_directories(unionman_telnet_login PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(my_ddns
    main.cpp
    cloudflare_ddns.cpp
    public_ip_resolver.cpp
    miwifi.cpp
)

target_link_libraries(my_ddns PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    swsc
)

target_include_directories(my_ddns PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(test_client
    test.cpp
)

target_link_libraries(test_client PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_include_directories(test_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(test_client PRIVATE -DUSE_SWSCLIB)
target_link_libraries(test_client PRIVATE swsc)
