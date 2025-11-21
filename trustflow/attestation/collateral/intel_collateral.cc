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

#include "trustflow/attestation/collateral/intel_collateral.h"

#include "sgx_dcap_quoteverify.h"
#include "sgx_ql_lib_common.h"
#include "yacl/base/exception.h"

#include "trustflow/attestation/utils/json2pb.h"
#include "trustflow/attestation/utils/bin2str.h"

namespace trustflow {
namespace attestation {
namespace collateral {

namespace {

// if the last byte is '\0', remove it,
// or \u0000\\\ will be in json_collateral, and the report can not be verified
void CharArray2String(const char *buf, const uint32_t buf_len,
                      std::string &str) {
  if (buf[buf_len - 1] == '\0') {
    str.assign(buf, buf_len - 1);
  } else {
    str.assign(buf, buf_len);
  }
}

}  // namespace

void GetIntelCollateral(
    const std::string &quote, const uint32_t quote_size,
    secretflowapis::v2::sdc::SgxQlQveCollateral &collateral) {
  uint8_t *p_quote_collateral = nullptr;
  uint32_t collateral_size = 0;
  int ret =
      tee_qv_get_collateral(reinterpret_cast<const uint8_t *>(quote.data()),
                            quote_size, &p_quote_collateral, &collateral_size);
  YACL_ENFORCE(ret == quote3_error_t::SGX_QL_SUCCESS && p_quote_collateral,
               "tee_qv_get_collateral err: {:#x}", ret);
  auto p_collateral_t =
      reinterpret_cast<sgx_ql_qve_collateral_t *>(p_quote_collateral);
  // copy values to pb
  collateral.set_version(p_collateral_t->version);

  std::string pck_crl_issuer_chain;
  CharArray2String(p_collateral_t->pck_crl_issuer_chain,
                   p_collateral_t->pck_crl_issuer_chain_size,
                   pck_crl_issuer_chain);
  collateral.set_pck_crl_issuer_chain(std::move(pck_crl_issuer_chain));

  std::string root_ca_crl;
  utils::CharArrayBinaryToEscapedString(reinterpret_cast<const uint8_t*>(p_collateral_t->root_ca_crl),
                   p_collateral_t->root_ca_crl_size, root_ca_crl);
  collateral.set_root_ca_crl(std::move(root_ca_crl)); 

  std::string pck_crl;
  utils::CharArrayBinaryToEscapedString(reinterpret_cast<const uint8_t*>(p_collateral_t->pck_crl), p_collateral_t->pck_crl_size, pck_crl);
  collateral.set_pck_crl(std::move(pck_crl));

  std::string tcb_info_issuer_chain;
  CharArray2String(p_collateral_t->tcb_info_issuer_chain,
                   p_collateral_t->tcb_info_issuer_chain_size,
                   tcb_info_issuer_chain);
  collateral.set_tcb_info_issuer_chain(std::move(tcb_info_issuer_chain));

  std::string tcb_info;
  CharArray2String(p_collateral_t->tcb_info, p_collateral_t->tcb_info_size,
                   tcb_info);
  collateral.set_tcb_info(std::move(tcb_info));

  std::string qe_identity_issuer_chain;
  CharArray2String(p_collateral_t->qe_identity_issuer_chain,
                   p_collateral_t->qe_identity_issuer_chain_size,
                   qe_identity_issuer_chain);
  collateral.set_qe_identity_issuer_chain(std::move(qe_identity_issuer_chain));

  std::string qe_identity;
  CharArray2String(p_collateral_t->qe_identity,
                   p_collateral_t->qe_identity_size, qe_identity);
  collateral.set_qe_identity(std::move(qe_identity));

  collateral.set_tee_type(p_collateral_t->tee_type);

  if (p_quote_collateral) {
    tee_qv_free_collateral(p_quote_collateral);
  }
}

}  // namespace collateral
}  // namespace attestation
}  // namespace trustflow