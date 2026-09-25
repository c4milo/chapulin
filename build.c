// The build record this object exports (build.h). Each field is the
// CH_BUILD_ macro of the same name, computed under the defines this
// object is compiled with, so a consumer that computes the same macros
// under its own defines reads equal values exactly when the two agree.
// build.h maps ch_build to the name this object's transport gives it,
// so the definition below is ch_build_tls, ch_build_record or
// ch_build_quic.
#include "build.h"

const ch_build_info ch_build = {
    .version = CH_BUILD_VERSION,
    .axes = CH_BUILD_AXES,
    .sizeof_ch_cfg = CH_BUILD_SIZEOF_CH_CFG,
    .sizeof_ch_tls = CH_BUILD_SIZEOF_CH_TLS,
    .sizeof_ch_ticket = CH_BUILD_SIZEOF_CH_TICKET,
    .sizeof_ch_record = CH_BUILD_SIZEOF_CH_RECORD,
    .sizeof_ch_quic = CH_BUILD_SIZEOF_CH_QUIC,
    .sizeof_ch_rsa_priv = CH_BUILD_SIZEOF_CH_RSA_PRIV,
    .tx_stage = CH_BUILD_TX_STAGE,
    .min_rxbuf = CH_BUILD_MIN_RXBUF,
    .x509_max = CH_BUILD_X509_MAX,
    .transport_params_max = CH_BUILD_TRANSPORT_PARAMS_MAX,
};
