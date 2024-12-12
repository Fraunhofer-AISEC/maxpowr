cmake_minimum_required(VERSION 3.16)
project(Endpoint)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
find_package(Boost 1.36.0 REQUIRED COMPONENTS program_options)

file(GLOB endpoint_files CONFIGURE_DEPENDS
        "Endpoint.cpp"
        "Decryptor.cpp"
        "Utils/ProgressUtils.cpp"
)

include_directories(${Boost_INCLUDE_DIRS})
add_executable(endpoint ${endpoint_files})
target_link_libraries(endpoint OpenSSL::Crypto Boost::program_options)

file(GLOB stackshot_files "*.stackshot.txt")
set_property(TARGET endpoint APPEND PROPERTY ADDITIONAL_CLEAN_FILES
        "progress.ckpt"
        ${stackshot_files}
)
