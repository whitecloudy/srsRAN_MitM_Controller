#ifndef __UE_PACKET_HANDLER__
#define __UE_PACKET_HANDLER__

#include <iostream>
#include <unistd.h>
#include <string>

#include "mitm_lib/asn1/asn1_utils.h"

namespace UE
{
    int decode_packet(uint8_t * buf, int n, asn1::json_writer & json_buffer);
    int encode_packet(std::string json_buf, uint8_t * buf);
}

#endif