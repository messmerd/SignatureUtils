cmake_minimum_required(VERSION 3.10)

project(SignatureUtils)

if(NOT WIN32)
    message(FATAL_ERROR "SignatureUtils is only available on Windows")
endif()

enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SRC
    ${PROJECT_SOURCE_DIR}/SignatureUtils.cpp
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

add_library(${PROJECT_NAME} STATIC ${SRC})
target_link_libraries(${PROJECT_NAME} PRIVATE crypt32)

add_executable(example example.cpp)
target_link_libraries(example ${PROJECT_NAME})
