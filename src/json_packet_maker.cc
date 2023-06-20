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
#include "../src/ue_packet_handler.h"
#include "../src/gnb_packet_handler.h"

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
  const char* rrcSetupComplete = "rrcSetupComplete";

  int isSetupComplete = 0;

  // NAS
  const char* dlInfoTransfer = "dlInformationTransfer";

  const char* criticalExtension = "criticalExtensions";
  const char* rat_type = "rat-Type";

  int rrcTransactionIdentifier = 0;
  int plmnIdentity = 0;
  std::string dedicatedNAS = "";
  std::string cipheringAlgorithm = "";
  std::string integrityAlgorithm = "";
  std::string lateNonCritExts = "";

  uint8_t waitTime = 0;
  std::string ratType = "";
  std::string capReqFilter = "";

  for (Value::ConstValueIterator itrr = d.Begin(); itrr != d.End(); ++itrr) {
    const Value& o = *itrr;
    if (isSetupComplete == 1) {
      break;
    }
    std::cout << "I'm Here" << std::endl;

  for (Value::ConstValueIterator itr = o.Begin(); itr != o.End(); ++itr) {
    const Value& obj = *itr;
    if (isSetupComplete == 1) {
      break;
    }
    std::cout << "I'm Here2" << std::endl;
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

		   else if (strcmp(rrcSetupComplete, content->name.GetString()) == 0) { // If RRC Setup Complete (RRC + NAS)
		     const Value& obj7 = content->value;

		     for(Value::ConstMemberIterator plmn = obj7.MemberBegin(); plmn != obj7.MemberEnd(); ++plmn) {
                       std::cout << plmn->name.GetString() << ": ";
		       if (plmn->value.IsInt()) {
                         plmnIdentity = plmn->value.GetInt();
		       }

		       else {
                         dedicatedNAS = plmn->value.GetString();
		       }
		     }

		     std::cout << "RRC Setup Complete with Dedicated NAS Msg" << std::endl;
		     std::cout << buf << std::endl;
		     ++itrr;
		     const Value& obj_ = *itrr;
		     handle_rrc_setup_complete(original_msg, rrcTransactionIdentifier, plmnIdentity, dedicatedNAS, size, obj_);
		     isSetupComplete = 1;
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

void jsonPacketMaker::handle_rrc_setup_complete(uint8_t* original_msg, int rrcTransactionIdentifier, int plmnIdentity, std::string dedicatedNAS, int size, const Value& obj) {
  struct msg_struct {
    uint32_t channel;
    uint8_t msg[32768];
  } msg_buffer;

  // 5GS Mobility Management
  std::string extended_protocol_discriminator = "";
  std::string security_header_type = "";
  std::string message_type = "";

  // ngKSI
  std::string security_context_flag = "";
  std::string nas_key_set_identifier = "";

  // 5GS Registration Type
  std::string follow_on_request_bit = "";
  std::string gs_registration_type_value = "";

  // 5GS Mobile Identity
  std::string type_of_identity = "";
  std::string supi_formats = "";
  unsigned int mcc = 0;
  unsigned int mnc = 0;
  int routing_indicator = 0;
  std::string protection_scheme_id = "";
  int home_network_public_key_identifier = 0;
  std::string scheme_output = "";

  // UE Security Capability
  int _5g_ea0 = 0;
  int _128_5g_ea1 = 0;
  int _128_5g_ea2 = 0;
  int _128_5g_ea3 = 0;
  int _5g_ea4 = 0;
  int _5g_ea5 = 0;
  int _5g_ea6 = 0;
  int _5g_ea7 = 0;
  int _5g_ia0 = 0;
  int _128_5g_ia1 = 0;
  int _128_5g_ia2 = 0;
  int _128_5g_ia3 = 0;
  int _5g_ia4 = 0;
  int _5g_ia5 = 0;
  int _5g_ia6 = 0;
  int _5g_ia7 = 0;

  std::cout << "\n" << std::endl;
  std::cout << "Spoofing RRC Setup Complete" << std::endl;
  std::cout << "RRC Transaction Identifier: " << rrcTransactionIdentifier << std::endl;
  std::cout << "Selected PLMN Identity: " << plmnIdentity << std::endl;
  std::cout << "Dedicated NAS Message: " << dedicatedNAS << std::endl;

  asn1::rrc_nr::ul_dcch_msg_s ul_dcch_msg;
  asn1::rrc_nr::rrc_setup_complete_ies_s* rrc_setup_complete = &ul_dcch_msg.msg.set_c1().set_rrc_setup_complete().crit_exts.set_rrc_setup_complete();
  ul_dcch_msg.msg.c1().rrc_setup_complete().rrc_transaction_id = rrcTransactionIdentifier;

  rrc_setup_complete->sel_plmn_id = plmnIdentity;
  rrc_setup_complete->registered_amf_present = false;
  rrc_setup_complete->guami_type_present = false;
  rrc_setup_complete->ng_minus5_g_s_tmsi_value_present = false;

  // Transform NAS JSON into NAS Message
  for (Value::ConstValueIterator itr = obj.Begin(); itr != obj.End(); ++itr) {
    const Value& o = *itr;
    for (Value::ConstMemberIterator mm = o.MemberBegin(); mm != o.MemberEnd(); ++mm) {
      //std::cout << "GOT" << std::endl;
      std::cout << mm->name.GetString() << ": " << std::endl;

      const Value& obj2 = mm->value;
      for (Value::ConstMemberIterator msg = obj2.MemberBegin(); msg != obj2.MemberEnd(); ++msg) {
        std::cout << msg->name.GetString() << ": ";
	if (strcmp(msg->name.GetString(), "Extended protocol discriminator") == 0) {
          std::cout << msg->value.GetString() << ", " << std::endl;
	  extended_protocol_discriminator = msg->value.GetString();
	}

	else if (strcmp(msg->name.GetString(), "Security header type") == 0) {
          std::cout << msg->value.GetString() << ", " << std::endl;
	  security_header_type = msg->value.GetString();
	}

	else if (strcmp(msg->name.GetString(), "Message type") == 0) {
          std::cout << msg->value.GetString() << ", " << std::endl;
	  message_type = msg->value.GetString();
	}

	else if (strcmp(msg->name.GetString(), "Registration request") == 0) {
          const Value& obj3 = msg->value;

	  for (Value::ConstMemberIterator request = obj3.MemberBegin(); request != obj3.MemberEnd(); ++request) {
            std::cout << request->name.GetString() << ": " << std::endl;

	    const Value& obj4 = request->value;
	    for (Value::ConstMemberIterator fields = obj4.MemberBegin(); fields != obj4.MemberEnd(); ++fields) {
              std::cout << fields->name.GetString() << ": ";

	      if (strcmp(fields->name.GetString(), "Security context flag") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		security_context_flag = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "Nas key set identifier") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		nas_key_set_identifier = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "Follow-on request bit(FOR)") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		follow_on_request_bit = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "5GS registration type value") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		gs_registration_type_value = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "Type of identity") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		type_of_identity = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "SUPI format") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		supi_formats = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "MCC") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		mcc = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "MNC") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		mnc = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "Routing indicator") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		routing_indicator = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "Protection scheme Id") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		protection_scheme_id = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "Home network public key identifier") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		home_network_public_key_identifier = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "Scheme output") == 0) {
                std::cout << fields->value.GetString() << ", " << std::endl;
		scheme_output = fields->value.GetString();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-EA0") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ea0 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "128-5G-EA1") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_128_5g_ea1 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "128-5G-EA2") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_128_5g_ea2 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "128-5G-EA3") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_128_5g_ea3 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-EA4") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ea4 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-EA5") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ea5 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-EA6") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ea6 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-EA7") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ea7 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-IA0") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ia0 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "128-5G-IA1") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_128_5g_ia1 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "128-5G-IA2") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_128_5g_ia2 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "128-5G-IA3") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_128_5g_ia3 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-IA4") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ia4 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-IA5") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ia5 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-IA6") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ia6 = fields->value.GetInt();
	      }

	      else if (strcmp(fields->name.GetString(), "5G-IA7") == 0) {
                std::cout << fields->value.GetInt() << ", " << std::endl;
		_5g_ia7 = fields->value.GetInt();
	      }

	      else {
                std::cout << "Undefined Field Error" << std::endl;
	      }
	    }
	  }
	}
      }
    }
  }

  srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
  if (!nas_msg) {
    std::cout << "Couldn't allocate NAS Message" << std::endl;
  }

  srsran::nas_5g::nas_5gs_msg initial_registration_request_stored;
  // Extended Protocol Discriminator
  if (strcmp(extended_protocol_discriminator.c_str(), "5gmm") == 0) {
    initial_registration_request_stored.hdr.extended_protocol_discriminator = srsran::nas_5g::nas_5gs_hdr::extended_protocol_discriminator_opts::extended_protocol_discriminator_5gmm;
  }

  else {
    initial_registration_request_stored.hdr.extended_protocol_discriminator = srsran::nas_5g::nas_5gs_hdr::extended_protocol_discriminator_opts::extended_protocol_discriminator_5gsm;
  }

  // Security Header Type
  if (strcmp(security_header_type.c_str(), "Plain 5gs nas message") == 0) {
    initial_registration_request_stored.hdr.security_header_type = srsran::nas_5g::nas_5gs_hdr::security_header_type_opts::plain_5gs_nas_message;
  }

  else if (strcmp(security_header_type.c_str(), "Integrity protected") == 0) {
    initial_registration_request_stored.hdr.security_header_type = srsran::nas_5g::nas_5gs_hdr::security_header_type_opts::integrity_protected;
  }

  else if (strcmp(security_header_type.c_str(), "Integrity protected and ciphered") == 0) {
    initial_registration_request_stored.hdr.security_header_type = srsran::nas_5g::nas_5gs_hdr::security_header_type_opts::integrity_protected_and_ciphered;
  }

  else if (strcmp(security_header_type.c_str(), "Integrity protected with new 5g nas context") == 0) {
    initial_registration_request_stored.hdr.security_header_type = srsran::nas_5g::nas_5gs_hdr::security_header_type_opts::integrity_protected_with_new_5G_nas_context;
  }

  else if (strcmp(security_header_type.c_str(), "Integrity protected and ciphered with new 5g nas context") == 0) {
    initial_registration_request_stored.hdr.security_header_type = srsran::nas_5g::nas_5gs_hdr::security_header_type_opts::integrity_protected_and_ciphered_with_new_5G_nas_context;
  }

  else {
    initial_registration_request_stored.hdr.security_header_type = srsran::nas_5g::nas_5gs_hdr::security_header_type_opts::plain_5gs_nas_message;
  }

  // Message Type (Only Uplink)
  if (strcmp(message_type.c_str(), "Registration request") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::registration_request;
  }

  else if (strcmp(message_type.c_str(), "Registration complete") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::registration_complete;
  }

  else if (strcmp(message_type.c_str(), "Deregistration request ue originating") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::deregistration_request_ue_originating;
  }

  else if (strcmp(message_type.c_str(), "Deregistration accept ue originating") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::deregistration_accept_ue_originating;
  }

  else if (strcmp(message_type.c_str(), "Service request") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::service_request;
  }

  else if (strcmp(message_type.c_str(), "Authentication response") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::authentication_response;
  }

  else if (strcmp(message_type.c_str(), "Identity response") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::identity_response;
  }

  else if (strcmp(message_type.c_str(), "Security mode complete") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::security_mode_complete;
  }

  else if (strcmp(message_type.c_str(), "Security mode reject") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::security_mode_reject;
  }

  else if (strcmp(message_type.c_str(), "Ul nas transport") == 0) {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::ul_nas_transport;
  }

  else {
    initial_registration_request_stored.hdr.message_type = srsran::nas_5g::msg_opts::options::nulltype;
  }

  srsran::nas_5g::registration_request_t& reg_req = initial_registration_request_stored.set_registration_request();
  
  // Security Context Flag
  if (strcmp(security_context_flag.c_str(), "native security context") == 0) {
    //reg_req.key_set_identifier_t.security_context_flag = srsran::nas_5g::key_set_identifier_t::security_context_flag_type_::options::native_security_context;
    reg_req.ng_ksi.security_context_flag = srsran::nas_5g::key_set_identifier_t::security_context_flag_type_::options::native_security_context;
  }

  else {
    //reg_req.key_set_identifier_t.security_context_flag = srsran::nas_5g::key_set_identifier_t::security_context_flag_type_::options::mapped_security_context;
    reg_req.ng_ksi.security_context_flag = srsran::nas_5g::key_set_identifier_t::security_context_flag_type_::options::mapped_security_context;
  }

  // Nas Key Set identifier (Only one option)
  reg_req.ng_ksi.nas_key_set_identifier = srsran::nas_5g::key_set_identifier_t::nas_key_set_identifier_type_::options::no_key_is_available_or_reserved;

  // Follow-on Request Pending
  if (strcmp(follow_on_request_bit.c_str(), "follow_on_request_pending") == 0) {
    reg_req.registration_type_5gs.follow_on_request_bit = srsran::nas_5g::registration_type_5gs_t::follow_on_request_bit_type_::options::follow_on_request_pending;
  }

  else {
    reg_req.registration_type_5gs.follow_on_request_bit = srsran::nas_5g::registration_type_5gs_t::follow_on_request_bit_type_::options::no_follow_on_request_pending;
  }

  // 5GS Registration Type Value
  if (strcmp(gs_registration_type_value.c_str(), "Initial Registration") == 0) {
    reg_req.registration_type_5gs.registration_type = srsran::nas_5g::registration_type_5gs_t::registration_type_type_::options::initial_registration;
  }

  else if (strcmp(gs_registration_type_value.c_str(), "Mobility Registration Updating") == 0) {
    reg_req.registration_type_5gs.registration_type = srsran::nas_5g::registration_type_5gs_t::registration_type_type_::options::mobility_registration_updating;
  }

  else if (strcmp(gs_registration_type_value.c_str(), "Periodic Registration Updating") == 0) {
    reg_req.registration_type_5gs.registration_type = srsran::nas_5g::registration_type_5gs_t::registration_type_type_::options::periodic_registration_updating;
  }

  else if (strcmp(gs_registration_type_value.c_str(), "Emergency Registration") == 0) {
    reg_req.registration_type_5gs.registration_type = srsran::nas_5g::registration_type_5gs_t::registration_type_type_::options::emergency_registration;
  }

  else {
    reg_req.registration_type_5gs.registration_type = srsran::nas_5g::registration_type_5gs_t::registration_type_type_::options::reserved;
  }

  // Type of Identity
  if (strcmp(type_of_identity.c_str(), "SUCI") == 0) {
    srsran::nas_5g::mobile_identity_5gs_t::suci_s& suci = reg_req.mobile_identity_5gs.set_suci();
    
    // SUPI Format (for SUCI)
    if (strcmp(supi_formats.c_str(), "IMSI") == 0) {
      suci.supi_format = srsran::nas_5g::mobile_identity_5gs_t::suci_s::supi_format_type_::options::imsi;
    }

    else if (strcmp(supi_formats.c_str(), "GCI") == 0) {
      suci.supi_format = srsran::nas_5g::mobile_identity_5gs_t::suci_s::supi_format_type_::options::gci;
    }

    else if (strcmp(supi_formats.c_str(), "GLI") == 0) {
      suci.supi_format = srsran::nas_5g::mobile_identity_5gs_t::suci_s::supi_format_type_::options::gli;
    }

    else {
      suci.supi_format = srsran::nas_5g::mobile_identity_5gs_t::suci_s::supi_format_type_::options::network_specific_identifier;
    }

    // MCC & MNC & Scheme Output (for SUCI)
    std::array<uint8_t, 3> mcc_arr;
    std::array<uint8_t, 3> mnc_arr;
    std::array<uint8_t, 4> routing_indicator_arr;
    std::vector<uint8_t> scheme_output_vec;

    std::string mcc_str = "";
    std::string mnc_str = "";

    std::stringstream ss;
    ss << std::hex << mcc;
    mcc_str = ss.str();

    std::stringstream ss2;
    ss2 << std::hex << mnc;
    mnc_str = ss2.str();

    if (mcc_str.length() != 5 || mnc_str.length() != 5) {
      mcc_arr[0] = 9;
      mcc_arr[1] = 0;
      mcc_arr[2] = 1;

      mnc_arr[0] = 7;
      mnc_arr[1] = 0;
      mnc_arr[2] = 0xf;
    }

    else {
      mcc_arr[0] = (int)mcc_str[0];
      mnc_arr[0] = (int)mnc_str[0];

      if (mcc_str[2] == 'f') {
        mcc_arr[1] = 0xf;
      }

      else {
        mcc_arr[1] = (int)mcc_str[2];

	if (mcc_str[4] == 'f') {
          mcc_arr[2] = 0xf;
	}

	else {
          mcc_arr[2] = (int)mcc_str[4];
	}
      }

      if (mnc_str[2] == 'f') {
        mnc_arr[1] = 0xf;
      }

      else {
        mnc_arr[1] = (int)mnc_str[2];

	if (mnc_str[4] == 'f') {
          mnc_arr[2] = 0xf;
	}

	else {
          mnc_arr[2] = (int)mnc_str[4];
	}
      }
    }

    for (int i=0; i<3; i++) {
      suci.mcc[i] = mcc_arr[i];
      suci.mnc[i] = mnc_arr[i];
    }

    suci.scheme_output.resize(5);
    for (int i=0; i<5; i++) {
      suci.scheme_output[i] = (int)(scheme_output[i*2] - '0')*16 + (int)(scheme_output[i*2+1] - '0');
    }

    // Protection Scheme ID (for SUCI)
    if (strcmp(protection_scheme_id.c_str(), "Null scheme") == 0) {
      suci.protection_scheme_id = srsran::nas_5g::mobile_identity_5gs_t::suci_s::protection_scheme_id_type_::options::null_scheme;
    }

    else {
      suci.protection_scheme_id = srsran::nas_5g::mobile_identity_5gs_t::suci_s::protection_scheme_id_type_::options::ecies_scheme_profile_a;
    }
    
    // Routing Indicator (for SUCI)
    std::string routing_indicator_str = "";
    std::stringstream ss3;
    ss3 << std::hex << routing_indicator;
    routing_indicator_str = ss3.str();
    if (routing_indicator_str[0] != '0') {
      suci.routing_indicator[0] = (int)routing_indicator_str[0];

      if (routing_indicator_str[2] == 'f') {
        suci.routing_indicator[1] = 0xf;
        suci.routing_indicator[2] = 0xf;
        suci.routing_indicator[3] = 0xf;
      }

      else {
        suci.routing_indicator[1] = (int)routing_indicator_str[2];

	if (routing_indicator_str[4] == 'f') {
          suci.routing_indicator[2] = 0xf;
	  suci.routing_indicator[3] = 0xf;
	}

	else {
          suci.routing_indicator[2] = (int)routing_indicator_str[4];

	  if (routing_indicator_str[6] == 'f') {
            suci.routing_indicator[3] = 0xf;
	  }

	  else {
            suci.routing_indicator[3] = (int)routing_indicator_str[6];
	  }
	}
      }
    }

    // Home Network Public Key Identifier (for SUCI)
    suci.home_network_public_key_identifier = home_network_public_key_identifier;
  }

  else if (strcmp(type_of_identity.c_str(), "GUTI_5G") == 0) {
    srsran::nas_5g::mobile_identity_5gs_t::guti_5g_s& guti = reg_req.mobile_identity_5gs.set_guti_5g();

    // MCC & MNC (for GUTI_5G)
    std::array<uint8_t, 3> mcc_arr;
    std::array<uint8_t, 3> mnc_arr;
    std::array<uint8_t, 4> routing_indicator_arr;
    std::vector<uint8_t> scheme_output_vec;

    std::string mcc_str = "";
    std::string mnc_str = "";

    std::stringstream ss;
    ss << std::hex << mcc;
    mcc_str = ss.str();

    std::stringstream ss2;
    ss2 << std::hex << mnc;
    mnc_str = ss2.str();

    if (mcc_str.length() != 5 || mnc_str.length() != 5) {
      mcc_arr[0] = 9;
      mcc_arr[1] = 0;
      mcc_arr[2] = 1;

      mnc_arr[0] = 7;
      mnc_arr[1] = 0;
      mnc_arr[2] = 0xf;
    }

    else {
      mcc_arr[0] = (int)mcc_str[0];
      mnc_arr[0] = (int)mnc_str[0];

      if (mcc_str[2] == 'f') {
        mcc_arr[1] = 0xf;
      }

      else {
        mcc_arr[1] = (int)mcc_str[2];

	if (mcc_str[4] == 'f') {
          mcc_arr[2] = 0xf;
	}

	else {
          mcc_arr[2] = (int)mcc_str[4];
	}
      }

      if (mnc_str[2] == 'f') {
        mnc_arr[1] = 0xf;
      }

      else {
        mnc_arr[1] = (int)mnc_str[2];

	if (mnc_str[4] == 'f') {
          mnc_arr[2] = 0xf;
	}

	else {
          mnc_arr[2] = (int)mnc_str[4];
	}
      }
    }

    for (int i=0; i<3; i++) {
      guti.mcc[i] = mcc_arr[i];
      guti.mnc[i] = mnc_arr[i];
    }
  }

  reg_req.ue_security_capability_present = true;
  
  if (_5g_ea0 == 1) {
    reg_req.ue_security_capability.ea0_5g_supported = true;
  }

  if (_128_5g_ea1 == 1) {
    reg_req.ue_security_capability.ea1_128_5g_supported = true;
  }

  if (_128_5g_ea2 == 1) {
    reg_req.ue_security_capability.ea2_128_5g_supported = true;
  }

  if (_128_5g_ea3 == 1) {
    reg_req.ue_security_capability.ea3_128_5g_supported = true;
  }

  if (_5g_ea4 == 1) {
    reg_req.ue_security_capability.ea4_5g_supported = true;
  }

  if (_5g_ea5 == 1) {
    reg_req.ue_security_capability.ea5_5g_supported = true;
  }

  if (_5g_ea6 == 1) {
    reg_req.ue_security_capability.ea6_5g_supported = true;
  }

  if (_5g_ea7 == 1) {
    reg_req.ue_security_capability.ea7_5g_supported = true;
  }

  if (_5g_ia0 == 1) {
    reg_req.ue_security_capability.ia0_5g_supported = true;
  }

  if (_128_5g_ia1 == 1) {
    reg_req.ue_security_capability.ia1_128_5g_supported = true;
  }

  if (_128_5g_ia2 == 1) {
    reg_req.ue_security_capability.ia2_128_5g_supported = true;
  }

  if (_128_5g_ia3 == 1) {
    reg_req.ue_security_capability.ia3_128_5g_supported = true;
  }

  if (_5g_ia4 == 1) {
    reg_req.ue_security_capability.ia4_5g_supported = true;
  }

  if (_5g_ia5 == 1) {
    reg_req.ue_security_capability.ia5_5g_supported = true;
  }

  if (_5g_ia6 == 1) {
    reg_req.ue_security_capability.ia6_5g_supported = true;
  }

  if (_5g_ia7 == 1) {
    reg_req.ue_security_capability.ia7_5g_supported = true;
  }

  initial_registration_request_stored.pack(nas_msg);
  
  rrc_setup_complete->ded_nas_msg.resize(nas_msg->N_bytes);
  memcpy(rrc_setup_complete->ded_nas_msg.data(), nas_msg->msg, nas_msg->N_bytes);
   
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
  memcpy(msg_buffer.msg, pdu->msg, pdu->N_bytes);
  memcpy(msg_buffer_bytes, &msg_buffer, size);

  for (int i=0; i<size; i++) {
    std::cout << std::to_string(msg_buffer_bytes[i]) << " ";
  }
  std::cout << "\n";

  asn1::json_writer* json_buffer = new asn1::json_writer;
  json_buffer->start_array();
  int result = UE::decode_packet(msg_buffer_bytes, size, *json_buffer);
  json_buffer->end_array();
  std::cout << json_buffer->to_string() << std::endl;
  
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
