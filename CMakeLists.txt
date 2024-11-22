cmake_minimum_required(VERSION 3.10)

project(
	SignatureUtils
	VERSION 0.1
	LANGUAGES CXX)

if(NOT WIN32)
	message(FATAL_ERROR "SignatureUtils is only available on Windows")
endif()

option(BUILD_TESTS "Build test program" OFF)

set(SRC
	${PROJECT_SOURCE_DIR}/src/SignatureUtils.cpp
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

add_library(${PROJECT_NAME} STATIC ${SRC})

target_include_directories(${PROJECT_NAME} PUBLIC include)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD_REQUIRED ON)

target_link_libraries(${PROJECT_NAME} PRIVATE crypt32)

if(BUILD_TESTS)
	add_executable(example tests/example.cpp)
	target_link_libraries(example ${PROJECT_NAME})
endif()
