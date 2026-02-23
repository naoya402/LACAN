#ifndef TLS_FUNC_H  
#define TLS_FUNC_H 
#include "common_func.h"
// // #include "main.h"

#ifdef __cplusplus
extern "C" {
#endif

 
// typedef enum{ SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;
// extern const char *router_addresses[];
extern EVP_MD_CTX *mdctx1, *mdctx2;
// extern const char *policy[];
// extern const int POLICY_COUNT;
// 固定IV (テスト用 簡易実装)
extern const uint8_t fixed_tls_iv[12];
extern const uint8_t fixed_tls_key[32];
extern uint32_t nonce_counter;


// ========= L2/L3 (Ether/IPv4) ヘッダ =========
typedef struct {
    unsigned char dst[6];
    unsigned char src[6];
    uint16_t ethertype;    // 0x0800 = IPv4
} __attribute__((packed)) EthHdr;

typedef struct {
    uint8_t  ver_ihl;      // version(4) | IHL(4)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t hdr_checksum;
    uint32_t src;
    uint32_t dst;
    // options may follow (IHL>5)
} __attribute__((packed)) IPv4Hdr;


unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen);
void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]);
int aead_decrypt(const unsigned char key[KEY_LEN], const unsigned char *ct, size_t ct_len, const unsigned char sid[SID_LEN], const unsigned char iv[IV_LEN], const unsigned char tag[TAG_LEN], unsigned char *pt_out);
void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char *sig, size_t *siglen);
int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen);
void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char prev_addr[4],  unsigned char next_addr[4], unsigned char nnext_addr[4], const unsigned char *tau, unsigned char rand_val[4]);
size_t write_l2l3_min(unsigned char *buf, size_t buf_cap);
size_t ipv4_header_len_bytes(const IPv4Hdr *ip);
size_t l3_overlay_offset(const unsigned char *l2);
size_t build_overlay_setup_req(unsigned char *l2, size_t cap, const Packet *pkt);
size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt);
int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt);
int router_handle_forward(unsigned char *frame, Node *nodes);
int router_handle_reverse(unsigned char *frame, Node *nodes);
int router_handle_data_trans(unsigned char *frame, Node *nodes);

int US_NIZK_Confirm(US_CTX *us, unsigned char *message, size_t message_len,  BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **confirm_msg, size_t *confirm_len);
int US_NIZK_Disavow(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **disavow_msg, size_t *disavow_len);

void build_nonce(uint8_t *nonce_out, uint32_t counter);
int tls_encrypt(const unsigned char *pt, int pt_len, unsigned char **out, int *out_len);
int tls_decrypt(const unsigned char *in, int in_len, unsigned char **out_pt, int *out_pt_len);

#ifdef __cplusplus
}
#endif

#endif
