cmake_minimum_required(VERSION 3.21)

project(htmlParserTest)

set (SOURCES
	htmlParser_test.cpp
	${CMAKE_SOURCE_DIR}/../htmlParser.cpp)

include_directories(/home/pasha/http_1_1_server/include/)

add_compile_options(-g)

# add_definitions(TEST_FILE_DIR "${CMAKE_SOURCE_DIR}/")
add_compile_definitions(TEST_FILE_DIR="${CMAKE_SOURCE_DIR}/")

add_executable(htmlParserTest ${SOURCES})



