

set (SOURCES    ue_packet_handler.cc 
                gnb_packet_handler.cc
                nas_packet_handler.cc
		json_packet_maker.cc)

add_library(controller_src STATIC ${SOURCES})

target_link_libraries(controller_src    rrc_nr_asn1
                                        nas_5g_msg
                                        asn1_utils
                                        srsran_common)
