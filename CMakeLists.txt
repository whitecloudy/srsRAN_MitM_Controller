cmake_minimum_required(VERSION 3.1.0)
project(mitm VERSION 0.1.0)

include(CTest)
enable_testing()

set(THREADS_PREFER_PTHREAD_LAG ON)
find_package(Threads REQUIRED)

add_executable(mitm controller.cc)
target_link_libraries(mitm pthread)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
