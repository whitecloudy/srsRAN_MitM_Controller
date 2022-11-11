#include "ue_packet_handler.h"
#include <iostream>

#include "mitm_lib/asn1/rrc_nr.h"
#include "mitm_lib/common/byte_buffer.h"
#include "mitm_lib/common/common_nr.h"



asn1::json_writer * decode_ul_dcch(uint8_t * buf, int n);
asn1::json_writer * UE::decode_packet(uint8_t *buf, int n)
{
    struct from_ue_struct
    {
        uint32_t channel;
        uint8_t msg[32768];
    } buffer;
    
    memcpy(&buffer, buf, n);

    switch (static_cast<srsran::nr_srb>(buffer.channel))
    {
    case srsran::nr_srb::srb0:
        // ccch
        return decode_ul_dcch(buffer.msg, n - sizeof(uint32_t));
        break;
    case srsran::nr_srb::srb1:
    case srsran::nr_srb::srb2:
    case srsran::nr_srb::srb3:
        // dcch
        return decode_ul_dcch(buffer.msg, n - sizeof(uint32_t));
        break;
    default:
        std::string errcause = fmt::format("Invalid LCID=%d", buffer.channel);
        std::cerr <<errcause <<std::endl;
        break;
    }

    return NULL;
}

asn1::json_writer * decode_ul_dcch(uint8_t * buf, int n)
{
    // Right now we only consider DCCH message
    struct asn1::rrc_nr::ul_dcch_msg_s ul_dcch_msg;
    {
        asn1::cbit_ref bref(buf, n);
        if (ul_dcch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
            ul_dcch_msg.msg.type().value != asn1::rrc_nr::ul_dcch_msg_type_c::types_opts::c1)
        {
            std::cerr << "Failed to unpack UL-DCCH message" << std::endl;
            return NULL;
        }
    }

    asn1::json_writer *json_buf_p = new asn1::json_writer();
    ul_dcch_msg.to_json(*json_buf_p);

    return json_buf_p;
}

asn1::json_writer * decode_ul_ccch(uint8_t * buf, int n)
{
    struct asn1::rrc_nr::ul_ccch_msg_s ul_ccch_msg;
    {
        asn1::cbit_ref bref(buf, n);
        if (ul_ccch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
            ul_ccch_msg.msg.type().value != asn1::rrc_nr::ul_ccch_msg_type_c::types_opts::c1)
        {
            std::cerr << "Failed to unpack UL-CCCH message" << std::endl;
            return NULL;
        }
    }

    asn1::json_writer *json_buf_p = new asn1::json_writer();
    ul_ccch_msg.to_json(*json_buf_p);

    return json_buf_p;
}