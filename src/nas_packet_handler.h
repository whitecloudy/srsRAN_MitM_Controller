#ifndef __NAS_PACKET_HANDLER__
#define __NAS_PACKET_HANDLER__

#include "mitm_lib/asn1/nas_5g_msg.h"
#include "mitm_lib/common/byte_buffer.h"
#include "mitm_lib/common/common_nr.h"

int handle_nas_msg(srsran::unique_byte_buffer_t pdu, asn1::json_writer &json_buf_p);

#endif