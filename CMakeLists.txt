########################################################################
# Prevent in-tree builds
########################################################################
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Prevented in-tree build. This is bad practice.")
endif(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

cmake_minimum_required(VERSION 3.1.0)
project(mitm VERSION 0.1.0)


########################################################################
# External Library config
########################################################################
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

########################################################################
# Execution file setting
########################################################################

set (EXEC_LIB_LIST  rrc_nr_asn1
                    asn1_utils
                    srsran_common
                    controller_src)

add_subdirectory(lib)
add_subdirectory(src)

add_executable(mitm controller.cc)
target_link_libraries(mitm pthread ${EXEC_LIB_LIST})



