cmake_minimum_required(VERSION 3.21)

project(server)

set (SOURCES
	src/Server.cpp
	src/ServerCore.cpp
	src/htmlUtils.cpp
	src/Router.cpp
	src/empty_main.cpp
	
	# src/Resources.cpp
	# src/ServerDB.cpp
	# src/Participant.cpp
	# src/DB.cpp
	# sha256/sha256.c
	# src/htmlParser.cpp
	# src/SessionList.cpp
	# src/serverSIGNUP
	# src/Resource.cpp
	# src/main.cpp
)

# set (MAIN_CPP_FILE
	# src/main.cpp
	# src/Server.cpp)

set(CMAKE_CXX_STANDARD 17 REQUIRED)

# set_source_files_properties(${MAIN_CPP_FILE} PROPERTIES COMPILE_OPTIONS -g)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package(Boost 1.8.3 REQUIRED)
include_directories( ${Boost_INCLUDE_DIR} )

# add resources to cmake
add_compile_definitions(ABS_PATH="${CMAKE_SOURCE_DIR}")
add_compile_definitions(DB_PATH="${CMAKE_SOURCE_DIR}/build/users.db") #with ending `/'
add_compile_definitions(HTML_SRC_PATH="${CMAKE_SOURCE_DIR}/html_src")

# debug mode
# add_compile_definitions(DEBUG)
# add_compile_options(-g)

# add_compile_options(-Wall -Wextra)

add_executable(main ${SOURCES} ${MAIN_CPP_FILE})

target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/include/)
# target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/sha256/)

# I have boost then cmake cannot find it 
# target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/../boost_1_83_0/include/boost/)
# Use command below instead upper one 
# and uncomment find_package( Boost [YOUR VERSION ])

target_link_libraries( main PRIVATE ${Boost_LIBRARIES} )

# target_link_libraries(main PRIVATE sqlite3)
target_link_libraries(main PRIVATE microhttpd)
target_link_libraries(main PRIVATE Threads::Threads)
target_link_libraries(main PRIVATE ${Boost_LIBRARIES})