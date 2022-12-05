#include "nas_packet_handler.h"

void write_encrypted_nas_pdu(srsran::unique_byte_buffer_t &pdu, asn1::json_writer &j);

int handle_nas_msg(srsran::unique_byte_buffer_t pdu, asn1::json_writer &json_buf_p)
{
    using namespace srsran::nas_5g;

    nas_5gs_msg nas_msg;

    if (nas_msg.unpack_outer_hdr(pdu) != SRSRAN_SUCCESS)
    {
        fprintf(stderr, "Unable to unpack outer NAS header\n");
        return SRSRAN_ERROR;
    }

    switch (nas_msg.hdr.security_header_type)
    {
    case nas_5gs_hdr::security_header_type_opts::plain_5gs_nas_message:
    case nas_5gs_hdr::security_header_type_opts::integrity_protected:
    case nas_5gs_hdr::security_header_type_opts::integrity_protected_with_new_5G_nas_context:
        break;
    case nas_5gs_hdr::security_header_type_opts::integrity_protected_and_ciphered:
        write_encrypted_nas_pdu(pdu, json_buf_p);
        //fprintf(stderr, "We do not handle encrypted data\n");
        //   if (integrity_check(pdu.get()) == false) {
        //     fprintf(stderr,"Not handling NAS message with integrity check error");
        //     return SRSRAN_ERROR;
        //   } else {
        //     cipher_decrypt(pdu.get());
        //   }
        return SRSRAN_ERROR;
    case nas_5gs_hdr::security_header_type_opts::integrity_protected_and_ciphered_with_new_5G_nas_context:
        write_encrypted_nas_pdu(pdu, json_buf_p);
        //fprintf(stderr, "We do not handle encrypted data\n");
        return SRSRAN_ERROR;
    default:
        fprintf(stderr, "Not handling NAS message with unkown security header\n");
        break;
    }

    // Parse the message header
    if (nas_msg.unpack(pdu) != SRSRAN_SUCCESS)
    {
        fprintf(stderr, "Unable to unpack complete NAS pdu\n");
        return SRSRAN_ERROR;
    }

    nas_msg.to_json(json_buf_p);

    return 0;
}

void write_encrypted_nas_pdu(srsran::unique_byte_buffer_t &pdu, asn1::json_writer &j)
{
    j.start_array();
    j.start_obj();
    j.write_fieldname("Encrypted 5G NAS");
    j.start_obj();
    j.write_str("PDU", octstring_to_string(pdu->data(), pdu->size()));
    j.end_obj();
    j.end_obj();
    j.end_array();
}