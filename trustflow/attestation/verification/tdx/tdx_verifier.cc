// Copyright 2024 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "trustflow/attestation/verification/tdx/tdx_verifier.h"

#include "absl/strings/escaping.h"
#include "cppcodec/base64_rfc4648.hpp"
#include "sgx_dcap_quoteverify.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/ssl_hash.h"

#include "trustflow/attestation/common/constants.h"
#include "trustflow/attestation/utils/json2pb.h"
#include "trustflow/attestation/utils/bin2str.h"

namespace trustflow {
namespace attestation {
namespace verification {

namespace {

constexpr uint32_t kReportDataSize = 64;
// Intel SGX SDK specifies that the quote type must be 0x00000081 (TDX).
constexpr uint32_t kIntelTeeTypeTdx = 0x00000081;
// Intel SGX SDK specifies that the quote type must be 0x00000000 (SGX).
constexpr uint32_t kIntelTeeTypeSgx = 0x00000000;

using base64 = cppcodec::base64_rfc4648;
namespace ual = secretflowapis::v2::sdc;

inline void SetCollateral(const std::string& name, const std::string& value,
                          char** dest, uint32_t* length) {
  YACL_ENFORCE(!value.empty(), "Invalid collateral data: {}", name);
  *dest = const_cast<char*>(value.data());
  // +1 is the workaround for the code in qvl, size should include the end '\0'
  *length = value.size() + 1;
}

inline void SetCollateral(const std::string& name, const std::vector<uint8_t>& value,
                          char** dest, uint32_t* length) {
  YACL_ENFORCE(!value.empty(), "Invalid collateral data: {}", name);
  *dest = reinterpret_cast<char*>(const_cast<uint8_t*>(value.data()));
  *length = value.size();
}

inline void SetCollateralFromEscapedString(const std::string& name, const std::string& escaped_value,
                      std::vector<uint8_t>& storage, char** dest, uint32_t* length) {
  YACL_ENFORCE(!escaped_value.empty(), "Invalid collateral data: {}", name);
  storage = utils::EscapedStringToCharArrayBinary(escaped_value, true);
  if (storage.empty()) {
    YACL_THROW("Failed to decode escaped string for {}", name);
  }
  *dest = reinterpret_cast<char*>(storage.data());
  *length = storage.size();
}

void InitializeCollateralData(const ual::SgxQlQveCollateral& collateral,
                              sgx_ql_qve_collateral_t* collateral_data,
                              std::vector<uint8_t>& root_ca_crl_storage,
                              std::vector<uint8_t>& pck_crl_storage) {
  collateral_data->version = collateral.version();
  // Set the sgx_ql_qve_collateral_t with data pointer and size
  SetCollateral("pck_crl_issuer_chain", collateral.pck_crl_issuer_chain(),
                &(collateral_data->pck_crl_issuer_chain),
                &(collateral_data->pck_crl_issuer_chain_size));
  SetCollateralFromEscapedString("root_ca_crl", collateral.root_ca_crl(),
                root_ca_crl_storage,
                &(collateral_data->root_ca_crl),
                &(collateral_data->root_ca_crl_size));
  SetCollateralFromEscapedString("pck_crl", collateral.pck_crl(),
                pck_crl_storage,
                &(collateral_data->pck_crl),
                &(collateral_data->pck_crl_size));
  SetCollateral("tcb_info_issuer_chain", collateral.tcb_info_issuer_chain(),
                &(collateral_data->tcb_info_issuer_chain),
                &(collateral_data->tcb_info_issuer_chain_size));
  SetCollateral("tcb_info", collateral.tcb_info(), &(collateral_data->tcb_info),
                &(collateral_data->tcb_info_size));
  SetCollateral("qe_identity_issuer_chain",
                collateral.qe_identity_issuer_chain(),
                &(collateral_data->qe_identity_issuer_chain),
                &(collateral_data->qe_identity_issuer_chain_size));
  SetCollateral("qe_identity", collateral.qe_identity(),
                &(collateral_data->qe_identity),
                &(collateral_data->qe_identity_size));
}

inline std::string GetMrHex(const tee_measurement_t* mr) {
  return absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(&(mr->m)), sizeof(tee_measurement_t)));
}

std::string ParseReportBodyPfMeasurements(
    const sgx_report2_body_t* report_body) {
  // All TDX platform measurements together
  return absl::StrCat(GetMrHex(&(report_body->mr_seam)),
                      GetMrHex(&(report_body->mrsigner_seam)),
                      GetMrHex(&(report_body->mr_td)),
                      GetMrHex(&(report_body->mr_config_id)),
                      GetMrHex(&(report_body->mr_owner)),
                      GetMrHex(&(report_body->mr_owner_config)));
}

std::string ParseReportBodyBootMeasurements(
    const sgx_report2_body_t* report_body) {
  // All TDX boot measurements together
  return absl::StrCat(GetMrHex(&(report_body->rt_mr[0])),
                      GetMrHex(&(report_body->rt_mr[1])));
}

std::string ParseReportBodyTaMeasurements(sgx_report2_body_t* report_body) {
  // All TDX TA static measurements together
  return absl::StrCat(GetMrHex(&(report_body->rt_mr[2])),
                      GetMrHex(&(report_body->rt_mr[3])));
}

}  // namespace

void TdxAttestationVerifier::Init() {
  YACL_ENFORCE_EQ(report_.str_report_version(), kReportVersion,
                  "Only version {} is supported, but {}", kReportVersion,
                  report_.str_report_version());
  YACL_ENFORCE_EQ(report_.str_report_type(), ReportType::kReportTypePassport,
                  "Only {} is supported now, but {}",
                  ReportType::kReportTypePassport, report_.str_report_type());

  // Check the platform
  YACL_ENFORCE_EQ(report_.str_tee_platform(), Platform::kPlatformTdx,
                  "It's not {} platfrom, input platform is {}",
                  Platform::kPlatformTdx, report_.str_tee_platform());

  // Get the report data, which is serialized json string of DcapReport
  ual::DcapReport dcap_report;
  JSON2PB(report_.json_report(), &dcap_report);
  quote_ = base64::decode(dcap_report.b64_quote());
  if (!dcap_report.json_collateral().empty()) {
    JSON2PB(dcap_report.json_collateral(), &collateral_);
  }
}

void TdxAttestationVerifier::ParseUnifiedReport(
    ual::UnifiedAttestationAttributes& attrs) {
  attrs.set_str_tee_platform(report_.str_tee_platform());

  YACL_ENFORCE_GE(quote_.size(), sizeof(sgx_quote4_t),
                  "quote size:{} is less than sgx_quote4_t:{}", quote_.size(),
                  sizeof(sgx_quote4_t));
  YACL_ENFORCE_GE(quote_.size(), sizeof(sgx_quote5_t),
                  "quote size:{} is less than sgx_quote5_t:{}", quote_.size(),
                  sizeof(sgx_quote5_t));

  const sgx_quote4_t* pquote4 =
      reinterpret_cast<const sgx_quote4_t*>(quote_.data());
  const sgx_quote5_t* pquote5 =
      reinterpret_cast<const sgx_quote5_t*>(quote_.data());

  YACL_ENFORCE_EQ(pquote4->header.tee_type, kIntelTeeTypeTdx,
                  "Error tee_type in quote: {0:#X}", pquote4->header.tee_type);

  int quote_version = pquote4->header.version;
  sgx_report2_body_t* report_body = nullptr;
  if (quote_version == 4) {
    report_body = const_cast<sgx_report2_body_t*>(&(pquote4->report_body));
  } else if (quote_version == 5) {
    report_body = const_cast<sgx_report2_body_t*>(
        (const sgx_report2_body_t*)pquote5->body);
  } else {
    YACL_THROW("Error version in TDX quote: {}", quote_version);
  }

  // Platform Measurement
  attrs.set_hex_platform_measurement(
      ParseReportBodyPfMeasurements(report_body));

  // Boot Measurement
  attrs.set_hex_boot_measurement(ParseReportBodyBootMeasurements(report_body));

  // TA Measurement
  attrs.set_hex_ta_measurement(ParseReportBodyTaMeasurements(report_body));

  // User Data
  YACL_ENFORCE_EQ(kReportDataSize, sizeof(sgx_report_data_t),
                  "Report data size is not {}", kReportDataSize);
  uint32_t half_report_data_size = kReportDataSize >> 1;
  const char* p_report_data =
      reinterpret_cast<const char*>(&(report_body->report_data.d));
  // Export the lower 32 bytes as user data
  std::string hex_user_data = absl::BytesToHexString(
      absl::string_view(p_report_data, half_report_data_size));
  // Export the higher 32 bytes as public key hash
  std::string hex_public_key_hash = absl::BytesToHexString(absl::string_view(
      p_report_data + half_report_data_size, half_report_data_size));

  attrs.set_hex_user_data(hex_user_data);
  attrs.set_hex_hash_or_pem_pubkey(hex_public_key_hash);

  uint64_t flags =
      *(reinterpret_cast<uint64_t*>(&(report_body->td_attributes)));

  if ((flags & SGX_FLAGS_DEBUG) == SGX_FLAGS_DEBUG) {
    attrs.set_bool_debug_disabled("false");
  } else {
    attrs.set_bool_debug_disabled("true");
  }
}

void TdxAttestationVerifier::VerifyPlatform() {
  // Storage for binary CRL data (with null terminators)
  std::vector<uint8_t> root_ca_crl_storage;
  std::vector<uint8_t> pck_crl_storage;
  
  sgx_ql_qve_collateral_t collateral_data;
  InitializeCollateralData(collateral_, &collateral_data, root_ca_crl_storage, pck_crl_storage);

  // get supplemental data size
  uint32_t supplemental_data_size = 0;
  quote3_error_t dcap_ret =
      tdx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
  YACL_ENFORCE(dcap_ret == SGX_QL_SUCCESS,
               "Fail to get supplemental data size, error code: {}",
               (uint32_t)dcap_ret);
  YACL_ENFORCE_EQ(
      supplemental_data_size, sizeof(sgx_ql_qv_supplemental_t),
      "Size is not same with header definition in SGX SDK, please make sure "
      "you are using same version of SGX SDK and DCAP QVL.");

  // create buffer to save supplemental data
  yacl::Buffer supplemental(supplemental_data_size);

  // TODO: use trusted timer
  time_t current_time = time(NULL);
  sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
  uint32_t collateral_expiration_status = 1;

  dcap_ret = tdx_qv_verify_quote(
      quote_.data(), quote_.size(), &collateral_data, current_time,
      &collateral_expiration_status, &quote_verification_result,
      NULL,  // qve_report_info is NULL means qvl mode
      supplemental.size(), (uint8_t*)supplemental.data());
  YACL_ENFORCE(dcap_ret == SGX_QL_SUCCESS,
               "Fail to verify dcap quote, error code: {0:#x}",
               (uint32_t)dcap_ret);

  // check verification result
  switch (quote_verification_result) {
    case SGX_QL_QV_RESULT_OK:
      break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
      // TODO: Add warnning log
      break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
      YACL_THROW("Fail to verify dcap quote, quote verification result: {}",
                 (uint32_t)quote_verification_result);
  }
}

}  // namespace verification
}  // namespace attestation
}  // namespace trustflow