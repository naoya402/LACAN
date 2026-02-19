#ifndef DPDK_FUNC_H  
#define DPDK_FUNC_H 
#include "common_func.h"

#ifdef __cplusplus
extern "C" {
#endif


// 往路の測定用
extern __thread uint64_t for_verify_tau_cycles;
extern __thread uint64_t for_verify_pi_cycles;
extern __thread uint64_t for_com_c_cycles;
extern __thread uint64_t for_sign_pi_cycles;
extern __thread uint64_t for_conf_v_cycles;
extern __thread uint64_t for_sign_tau_cycles;

//データ転送の測定用
extern __thread uint64_t datatrans_gen_acseg_cycles;
extern __thread uint64_t datatrans_verify_acseg_cycles;

extern __thread EVP_MD_CTX *mdctx1, *mdctx2;


unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen);
void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]);
int aead_decrypt(const unsigned char key[KEY_LEN], const unsigned char *ct, size_t ct_len, const unsigned char sid[SID_LEN], const unsigned char iv[IV_LEN], const unsigned char tag[TAG_LEN], unsigned char *pt_out);
void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char *sig, size_t *siglen);
int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen);
void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char *prev_addr,  unsigned char *next_addr, unsigned char *nnext_addr, const unsigned char *tau, unsigned char rand_val[4]);
size_t read_l2l3_min(const unsigned char *frame, size_t frame_len);
size_t build_overlay_setup_req(struct rte_mbuf *mbuf, const Packet *pkt);
size_t build_overlay_data_trans(struct rte_mbuf *mbuf, const Packet *pkt);
int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt);
int router_handle_forward(struct rte_mbuf *mbuf, Node *nodes);
int router_handle_data_trans(struct rte_mbuf *mbuf, Node *nodes);

int US_NIZK_Confirm(US_CTX *us, unsigned char *message, size_t message_len,  BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **confirm_msg, size_t *confirm_len);
int US_NIZK_Disavow(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **disavow_msg, size_t *disavow_len);


#ifdef __cplusplus
}
#endif

#endif