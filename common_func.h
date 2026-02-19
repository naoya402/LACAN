#ifndef FUNC_H
#define FUNC_H


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string>
#include <random>
#include <cmath>
#include <utility>
#include <time.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_malloc.h>
#include <rte_flow.h>
#include <rte_thash.h>
#include <rte_atomic.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "dpdk-util/eth_config2.h"
#include "main.h"

#ifdef __cplusplus
extern "C" {
#endif

using namespace std;
#define CORE_NUM 10

#define MAX_FRAME 8192

#define ROUTERS 3
#define NODES   (ROUTERS+2)

#define ETH_LEN 14   // VLAN 無し
#define IP_LEN  20
#define SID_LEN 16
#define PUB_LEN 32
#define SEC_LEN 32
#define KEY_LEN 32
#define SEG_LEN 12  // c_i の長さ（固定長にする）
#define TAG_LEN 16
#define IV_LEN  12
#define MAX_SEG_CON (ROUTERS + 1) * (SEG_LEN + TAG_LEN + IV_LEN)
#define SIG_LEN 64
#define COM_LEN 32
#define USIG_LEN 33
#define GSIG_LEN 6100 // グループ署名の最大長 (適宜調整)
#define MAX_DH_PK (ROUTERS * PUB_LEN)
#define MAX_COM ((ROUTERS + 1) * COM_LEN)
#define MAX_PI ((ROUTERS + 1) * USIG_LEN)
#define ACSEG_LEN 16
// #define MAX_ACSEG_CON ROUTERS * ACSEG_LEN
#define MAX_PTXT 128 // メッセージペイロード最大長
// #define MAX_PKT  4096
#define MAX_STATE  10
#define PAD_LEN 32  // PAD_LEN*8 bit分のパディング 1ブロック=128bit
// #define FRAME_SIZE 4096

// #define CHECK_RC(rc, msg) \
//     do { if ((rc) != IOK) { fprintf(stderr, "ERROR %s: rc=%d\n", (msg), (rc)); exit(1);} } while(0)

#define CURVE_NID NID_secp256k1

typedef enum { SETUP_REQ = 1, SETUP_RESP = 2, DATA_TRANS = 3 } Status;
extern const char *router_addresses[];
extern const char *policy[];
extern const int POLICY_COUNT;
// extern __thread EVP_MD_CTX *mdctx1, *mdctx2;// 共通で使うのは避けるべき



// // 往路の測定用
// extern __thread uint64_t for_verify_tau_cycles;
// extern __thread uint64_t for_verify_pi_cycles;
// extern __thread uint64_t for_com_c_cycles;
// extern __thread uint64_t for_sign_pi_cycles;
// extern __thread uint64_t for_conf_v_cycles;
// extern __thread uint64_t for_sign_tau_cycles;

// //データ転送の測定用
// extern __thread uint64_t datatrans_gen_acseg_cycles;
// extern __thread uint64_t datatrans_verify_acseg_cycles;

// ---- 共通ヘッダ ----
// SID(16) | STATUS(1) | idx(1)
typedef struct {
    unsigned char sid[SID_LEN];  // セッションID
    uint8_t status;              // ステータス (SETUP_REQ, SETUP_RESP, DATA_TRANS)
    uint8_t idx;                 // インデックス (0=センダー, NODES-1=レシーバ)
    
    // SETUP_REQ
    unsigned char seg_concat[MAX_SEG_CON];         // 暗号化経路情報リストデータ
    unsigned char dh_pk_concat[MAX_DH_PK];   // DH公開鍵リストデータ
    unsigned char com_concat[MAX_COM];       // コミットメントリストデータ
    unsigned char pi_concat[MAX_PI];         // π リストデータ
    
    // DATA_TRANS ヘッダ: アカウンタビリティセグメント
    unsigned char acseg_concat[ROUTERS * ACSEG_LEN];       // アカウンタビリティセグメント

} Oheader;

// ---- ペイロード ----
typedef struct {
    
    // SETUP_REQ
    // uint16_t tau_len;
    unsigned char tau[SIG_LEN];       //検証用の署名
    unsigned char v[162];   //πのNIZK用の値
    size_t sig_len; // グループ署名長
    unsigned char sig_bytes[GSIG_LEN];  // グループ署名
    unsigned char ts[4];//timestamp
    
    // ---- SETUP_REQ / SETUP_RESP ----
    unsigned char peer_pub[PUB_LEN];  // 公開鍵 (k_C または k_S)

    // ---- DATA_TRANS ----
    unsigned char iv[IV_LEN];             // GCM-IV
    size_t ct_len;                        // 暗号文長
    unsigned char ct[MAX_PTXT + PAD_LEN]; // 暗号文 + Padding
    unsigned char tag[TAG_LEN];           // GCM-タグ

} Payload;

typedef struct {
    Oheader  h;
    Payload p;
} Packet;

typedef struct {
    int id; // ノードID (今回は便宜上0=センダー, NODES-1=レシーバ)
    unsigned char addr[4];


    // X25519 (DH)
    EVP_PKEY *dh_sk;
    EVP_PKEY *dh_pk;

    // X25519鍵
    EVP_PKEY *sk;
    EVP_PKEY *pk;

    // US 鍵
    BIGNUM *us_x; // 秘密鍵
    EC_POINT *us_y; // 公開鍵

    // セッション鍵
    //センダー,レシーバは全リレー分(k)、自リレー分のみ(ki)
    unsigned char k[NODES][KEY_LEN];//各リレーとの共有鍵
    unsigned char ki[KEY_LEN];//センダーと自リレーとの共有鍵
    unsigned char ki_R[KEY_LEN];//レシーバと自リレーとの共有鍵

    unsigned char sess_key[KEY_LEN];
    int has_sess;

    // SIDに紐づく前後ホップ状態
    struct {
        int used;
        unsigned char sid[SID_LEN];
        unsigned char prev_addr[4]; 
        unsigned char next_addr[4]; 
        unsigned char nnext_addr[4]; 
        unsigned char tau[SIG_LEN];   // τi
        unsigned char rand_val[4];
        unsigned char ct_hash[SHA256_DIGEST_LENGTH];
    } state[MAX_STATE];
} Node;

typedef struct {
    EC_GROUP *group;
    BIGNUM *order;
    BN_CTX *ctx;
} US_CTX; // US 公開パラメータ


void die(const char *msg);
void die_ossl(const char *msg);
void print_hex(const char *title, const unsigned char *s, size_t len);
EVP_PKEY* gen_x25519_keypair();
EVP_PKEY* gen_ed25519_keypair();
void save_ed25519_seckey_pem(EVP_PKEY *pkey, const char *filename);
void save_ed25519_pubkey_pem(EVP_PKEY *pkey, const char *filename);
EVP_PKEY* load_seckey_pem(const char *filename);
EVP_PKEY* load_pubkey_pem(const char *filename);
void get_raw_pub(EVP_PKEY *pkey, unsigned char pub[PUB_LEN]);
EVP_PKEY* import_x25519_pub(const unsigned char pub[PUB_LEN]);
void hash_sid(const unsigned char *sid_data, size_t sid_data_len, unsigned char sid[SID_LEN]);
void derive_shared(const EVP_PKEY *my_sk, const EVP_PKEY *peer_pub, unsigned char sec[SEC_LEN]);
void init_crypto(EVP_PKEY *sk, EVP_PKEY *pk);
int aes_gmac(const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen, const unsigned char *data, size_t datalen, unsigned char out[ACSEG_LEN], unsigned int *out_len);
void node_init(Node *node, int id, const char *addr);
void node_free(Node *n);
// void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char prev_addr,  unsigned char next_addr, unsigned char nnext_addr, const unsigned char *tau, unsigned char rand_val[4]);
const unsigned char* state_get_next(const Node *n, const unsigned char sid[SID_LEN]);
const unsigned char* state_get_prev(const Node *n, const unsigned char sid[SID_LEN]);
const unsigned char* state_get_tau(const Node *n, const unsigned char sid[SID_LEN]);
int save_pi_list(const unsigned char sid[SID_LEN], const unsigned char *pi_concat, size_t pi_len);
int load_pi_list(const char *filename, unsigned char sid[SID_LEN], unsigned char **pi_out, size_t *pi_len_out);
int apply_policy_contract(const char *msg);
US_CTX* US_init(const char *curve_name);
void US_free(US_CTX *us);
int save_us_x_pem(BIGNUM *x, const char *filename);
BIGNUM *load_us_x_pem(const char *filename);
int hash_to_scalar(US_CTX *us, unsigned char *msg, size_t msglen, BIGNUM *out);
int US_sign(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *x, unsigned char **sig, size_t *sig_len);
int US_NIZK_VerifyC(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *confirm_msg, size_t confirm_len);
int US_NIZK_VerifyD(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *disavow_msg, size_t disavow_len);
void Commit256(const unsigned char *s_bytes, size_t s_len, const unsigned char *r_bytes, size_t r_len, unsigned char *out_commit);

#ifdef __cplusplus
}
#endif

#endif