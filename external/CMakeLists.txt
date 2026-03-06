add_library(swsc INTERFACE)

find_package(Threads REQUIRED)
target_link_libraries(swsc INTERFACE Threads::Threads)

target_include_directories(swsc INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                                            $<INSTALL_INTERFACE:include>)

target_compile_definitions(swsc INTERFACE ASIO_STANDALONE)

if(WIN32)
    target_link_libraries(swsc INTERFACE ws2_32 wsock32)
endif()

if(APPLE)
    if(EXISTS /usr/local/opt/openssl)
        set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
    elseif(EXISTS /opt/homebrew/opt/openssl)
        set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl)
    endif()
endif()

find_package(OpenSSL REQUIRED)
target_link_libraries(swsc INTERFACE OpenSSL::SSL OpenSSL::Crypto)
