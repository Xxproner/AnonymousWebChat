cmake_minimum_required(VERSION 3.21)

project(server)

set (SOURCES
	server.cpp
	# include/LyraArgs.hpp
	)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# find_package( Boost 1.8.3 COMPONENTS lexical_cast REQUIRED )

# include_directories( ${Boost_INCLUDE_DIR} )
# include_directories(~/boost/include)

add_compile_options(-g3)

# add_definitions()

add_compile_definitions(ABS_PATH="${CMAKE_SOURCE_DIR}/")
add_compile_definitions(DB_PATH="${CMAKE_SOURCE_DIR}/")
add_compile_definitions(HTML_SRC_PATH="${CMAKE_SOURCE_DIR}/html_src/")

add_executable(main ${SOURCES})

target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/include/)
target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/../boost_1_83_0/include/boost/)

# target_link_libraries( main LINK_PUBLIC ${Boost_LIBRARIES} )

# target_link_libraries( main LINK_PUBLIC ${Boost_LIBRARIES} )
target_link_libraries(main PRIVATE sqlite3)
target_link_libraries(main PRIVATE microhttpd)
target_link_libraries(main PRIVATE Threads::Threads)