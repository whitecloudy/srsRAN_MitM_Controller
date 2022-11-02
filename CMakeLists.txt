########################################################################
# Prevent in-tree builds
########################################################################
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Prevented in-tree build. This is bad practice.")
endif(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

cmake_minimum_required(VERSION 3.1.0)
project(mitm VERSION 0.1.0)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")

# Crypto
find_package(Polarssl)
if (POLARSSL_FOUND)
    set(SEC_INCLUDE_DIRS "${POLARSSL_INCLUDE_DIRS}")
    if(BUILD_STATIC)
        set(SEC_LIBRARIES    "${POLARSSL_STATIC_LIBRARIES}")
    else(BUILD_STATIC)
        set(SEC_LIBRARIES    "${POLARSSL_LIBRARIES}")
    endif(BUILD_STATIC)
    add_definitions(-DHAVE_POLARSSL)
else(POLARSSL_FOUND)
    find_package(MbedTLS REQUIRED)
    if (MBEDTLS_FOUND)
        set(SEC_INCLUDE_DIRS "${MBEDTLS_INCLUDE_DIRS}")
    if(BUILD_STATIC)
        set(SEC_LIBRARIES    "${MBEDTLS_STATIC_LIBRARIES}")
    else(BUILD_STATIC)
        set(SEC_LIBRARIES    "${MBEDTLS_LIBRARIES}")
    endif(BUILD_STATIC)
    add_definitions(-DHAVE_MBEDTLS)
    else(MBEDTLS_FOUND)
        message(FATAL_ERROR "Either PolarSSL or mbedTLS are required to build srsRAN")
    endif (MBEDTLS_FOUND)
endif(POLARSSL_FOUND)

#include(CTest)
#enable_testing()

#list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")
#include(SRSRANVersion)
#include(SRSRANPackage)

########################################################################
# Install Dirs
########################################################################
#if (NOT CMAKE_INSTALL_LIBDIR)
#    include(GNUInstallDirs)
#endif (NOT CMAKE_INSTALL_LIBDIR)

# Fall back to just "lib" if the item provided by GNUInstallDirs doesn't exist
#if (NOT EXISTS "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
#    message(STATUS "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} does not exist. Defaulting install location to ${CMAKE_INSTALL_PREFIX}/lib.")
#    set(CMAKE_INSTALL_LIBDIR lib)
#endif()

#set(RUNTIME_DIR bin)
#set(LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR})
#set(INCLUDE_DIR include)

add_subdirectory(lib)

#set(THREADS_PREFER_PTHREAD_LAG ON)
#find_package(Threads REQUIRED)

add_executable(mitm controller.cc)
target_link_libraries(mitm pthread)

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)

########################################################################
# Add headers to cmake project (useful for IDEs)
########################################################################
#set(HEADERS_ALL "")
#file(GLOB headers *)
#foreach(_header ${headers})
#    message(${_header})
#    if(IS_DIRECTORY ${_header})
#        file(GLOB_RECURSE tmp "${_header}/*.h")
#        list(APPEND HEADERS_ALL ${tmp})
#    endif(IS_DIRECTORY ${_header})
#endforeach()
#add_custom_target(add_srsran_headers SOURCES ${HEADERS_ALL})

