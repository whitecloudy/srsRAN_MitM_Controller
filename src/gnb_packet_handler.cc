#include "gnb_packet_handler.h"

#include "mitm_lib/asn1/rrc_nr.h"
#include "mitm_lib/common/byte_buffer.h"
#include "mitm_lib/common/common_nr.h"



asn1::json_writer * decode_dl_dcch(uint8_t * buf, int n);
asn1::json_writer * decode_dl_ccch(uint8_t * buf, int n);

asn1::json_writer * gNB::decode_packet(uint8_t * buf, int n)
{
    struct from_gnb_struct
    {
        uint32_t channel;
        uint8_t buf[32768];
    } buffer;
    
    memcpy(&buffer, buf, n);

    switch (static_cast<srsran::nr_srb>(buffer.channel))
    {
    case srsran::nr_srb::srb0:
        //ccch
        return decode_dl_ccch(buffer.buf, n - sizeof(buffer.channel));
        break;
    case srsran::nr_srb::srb1:
    case srsran::nr_srb::srb2:
        //dcch
        return decode_dl_dcch(buffer.buf, n - sizeof(buffer.channel));
        break;
    default:
        std::string errcause = fmt::format("Invalid LCID=%d", buffer.channel);
        std::cerr << errcause << std::endl;
        break;
    }

    return NULL;
}

asn1::json_writer * decode_dl_ccch(uint8_t * buf, int n)
{
    asn1::cbit_ref bref(buf, n);
    asn1::rrc_nr::dl_ccch_msg_s dl_ccch_msg;
    if (dl_ccch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
        dl_ccch_msg.msg.type().value != asn1::rrc_nr::dl_ccch_msg_type_c::types_opts::c1)
    {
        std::cerr << "Failed to unpack UL-DCCH message" << std::endl;
        return NULL;
    }

    asn1::json_writer *json_buf_p = new asn1::json_writer();
    dl_ccch_msg.to_json(*json_buf_p);

    return json_buf_p;
}

asn1::json_writer * decode_dl_dcch(uint8_t * buf, int n)
{
    asn1::cbit_ref bref(buf, n);
    asn1::rrc_nr::dl_dcch_msg_s dl_dcch_msg;
    if (dl_dcch_msg.unpack(bref) != asn1::SRSASN_SUCCESS or
        dl_dcch_msg.msg.type().value != asn1::rrc_nr::dl_dcch_msg_type_c::types_opts::c1)
    {
        std::cerr << "Failed to unpack UL-DCCH message" << std::endl;
        return NULL;
    }

    asn1::json_writer *json_buf_p = new asn1::json_writer();
    dl_dcch_msg.to_json(*json_buf_p);

    return json_buf_p;
}