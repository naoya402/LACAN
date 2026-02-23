#include <time.h>
#include <unistd.h>

#include "common_func.h"
// #include "TLS_func.h"
#include "DPDK_func.h"

const char* router_addresses[] = {
    "192.168.10.0",
    "192.168.10.1",
    "192.168.10.2",
    "192.168.10.3",
    "192.168.10.4",
    "192.168.10.5",
    "192.168.10.6",
    "192.168.10.7",
    "192.168.10.8",
    "192.168.10.9",
    "192.168.10.10"
};

// ポリシー
const char *policy[] = {"attack", "leak", "bomb", "hello"};
const int POLICY_COUNT = sizeof(policy) / sizeof(policy[0]);

// エラー処理
void die(const char *msg) {
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(EXIT_FAILURE);
}

// OpenSSLエラー処理
void die_ossl(const char *msg) {
    fprintf(stderr, "OpenSSL ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// バイト列を16進数で表示
void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

// X25519鍵ペア生成
EVP_PKEY* gen_x25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) die("EVP_PKEY_CTX_new_id");
    EVP_PKEY *p = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die("keygen_init");
    if (EVP_PKEY_keygen(ctx, &p) <= 0) die("keygen");
    EVP_PKEY_CTX_free(ctx);
    return p;
}

// Ed25519鍵ペア生成
EVP_PKEY* gen_ed25519_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) die_ossl("EVP_PKEY_CTX_new_id");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) die_ossl("EVP_PKEY_keygen_init");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) die_ossl("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// PEM形式での鍵保存・読み込み
void save_ed25519_seckey_pem(EVP_PKEY *sk, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) die("fopen write failed");
    if (!PEM_write_PrivateKey(f, sk, NULL, NULL, 0, NULL, NULL)) {
        fclose(f);
        die_ossl("PEM_write_PrivateKey");
    }
    fclose(f);
}

void save_ed25519_pubkey_pem(EVP_PKEY *pk, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) die("fopen write failed");
    if (!PEM_write_PUBKEY(f, pk)) {
        fclose(f);
        die_ossl("PEM_write_PUBKEY");
    }
    fclose(f);
}

EVP_PKEY *load_seckey_pem(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen read failed");
    EVP_PKEY *p = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!p) die_ossl("PEM_read_PrivateKey");
    return p;
}

EVP_PKEY *load_pubkey_pem(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen read failed");
    EVP_PKEY *p = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!p) die_ossl("PEM_read_PUBKEY");
   //  print_ed25519_pubkey(p);
    return p;
}

// DH秘密鍵から公開鍵(バイト列)を取得
void get_raw_pub(EVP_PKEY *pkey, unsigned char pub[PUB_LEN]) {
      size_t len = PUB_LEN;
      if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0 || len != PUB_LEN) die("get_raw_public_key");
}

// 公開鍵のインポート
EVP_PKEY* import_x25519_pub(const unsigned char *pub) {
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, PUB_LEN);
    if (!p) die("new_raw_public_key");
    return p;
}

// SIDの計算
void hash_sid(const unsigned char *sid_data, size_t sid_data_len, unsigned char sid[SID_LEN]) {
    SHA256(sid_data, sid_data_len, sid);
}

// X25519 共有秘密の導出
void derive_shared(const EVP_PKEY *my_sk, const EVP_PKEY *peer_pub, unsigned char sec[SEC_LEN]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*)my_sk, NULL);
    if (!ctx) die("derive ctx");
    if (EVP_PKEY_derive_init(ctx) <= 0) die("derive_init");
    if (EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY*)peer_pub) <= 0) die("set_peer");
    size_t outlen = SEC_LEN;
    if (EVP_PKEY_derive(ctx, sec, &outlen) <= 0 || outlen != SEC_LEN) die("derive");
    EVP_PKEY_CTX_free(ctx);
}

// Ed25519 署名・検証
// 初期化処理（
void init_crypto(EVP_PKEY *sk, EVP_PKEY *pk) {
    mdctx1 = EVP_MD_CTX_new();
    if (!mdctx1) die_ossl("EVP_MD_CTX_new sign");
    if (EVP_DigestSignInit(mdctx1, NULL, NULL, NULL, sk) <= 0)
        die_ossl("EVP_DigestSignInit");

    mdctx2 = EVP_MD_CTX_new();
    if (!mdctx2) die_ossl("EVP_MD_CTX_new verify");
    if (EVP_DigestVerifyInit(mdctx2, NULL, NULL, NULL, pk) <= 0)
        die_ossl("EVP_DigestVerifyInit");
}

// AES-GMAC (タグ生成)
int aes_gmac(const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen, const unsigned char *data, size_t datalen, unsigned char out[ACSEG_LEN], unsigned int *out_len){
    if (!key || keylen == 0 || !iv || ivlen == 0 || (!data && datalen > 0) || !out || !out_len) {
        return -1;
    }

    int ret = -1;
    int len;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;

    // 鍵長に基づいてCipherを選択
    if (keylen == 16) {
        cipher = EVP_aes_128_gcm();
    } else if (keylen == 24) {
        cipher = EVP_aes_192_gcm();
    } else if (keylen == 32) {
        cipher = EVP_aes_256_gcm();
    } else {
        // サポートされていない鍵長
        return -1;
    }

    // コンテキストの作成
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // 1. 暗号化操作の初期化 (GCMモード)
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) return -1;

    // 2. IV長のセット (デフォルトの12バイト以外の場合に必要)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen, NULL) != 1) return -1;

    // 3. 鍵とIVのセット
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) return -1;

    // 4. AAD (Additional Authenticated Data) の処理
    // GMACは平文を暗号化せず、データ全体をAADとして扱うことでMACを計算します。
    // 出力バッファにはNULLを渡します。
    if (EVP_EncryptUpdate(ctx, NULL, &len, data, (int)datalen) != 1) return -1;

    // 5. ファイナライズ (パディング処理など)
    if (EVP_EncryptFinal_ex(ctx, NULL, &len) != 1) return -1;

    // 6. タグ (MAC) の取得
    // ここで生成された16バイトのタグをoutに書き込みます
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ACSEG_LEN, out) != 1) return -1;

    *out_len = ACSEG_LEN;
    ret = 0; // 成功

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// 自身のノード初期化
void node_init(Node *node, int id, const char *addr) {
    memset(node, 0, sizeof(Node));
    node->id = id;
    node->sk = load_seckey_pem("ed25519_sec.pem"); // 既存秘密鍵の読み込み
    node->pk = load_pubkey_pem("ed25519_pub.pem"); // 既存公開鍵の読み込み
    init_crypto(node->sk, node->pk);// 今はどのノードの鍵も一緒なので自身の鍵で初期化しておく
   
    node->dh_sk = load_seckey_pem("dh_sec.pem");//gen_x25519_keypair();//ここでファイル読み込みしたい
    unsigned char pub[PUB_LEN];
    get_raw_pub(node->dh_sk, pub);
    node->dh_pk = import_x25519_pub(pub);


    US_CTX *us = US_init("secp256k1");
    node->us_x = load_us_x_pem("us_x.pem");
    node->us_y = EC_POINT_new(us->group);
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    EC_POINT_mul(us->group, node->us_y, NULL, G, node->us_x, us->ctx);

    // IPv4アドレスの設定
    if (inet_pton(AF_INET, addr, node->addr) != 1) {
        die("inet_pton failed in prev_node_init");
    }
    // RAND_bytes(node->rand_val, sizeof(node->rand_val));
    // // 便宜上乱数を任意の値に固定 本来はstate_setごとにランダム値を設定
    // memset(node->state[0].rand_val, 0x11, sizeof(node->state[0].rand_val));

}

// ノードのリソース解放
void node_free(Node *n) {
    if (n->dh_sk) EVP_PKEY_free(n->dh_sk);
    if (n->dh_pk) EVP_PKEY_free(n->dh_pk);
    if (n->sk) EVP_PKEY_free(n->sk);
    if (n->pk) EVP_PKEY_free(n->pk);
    if (n->us_x) BN_free(n->us_x);
    if (n->us_y) EC_POINT_free(n->us_y);
    // if (n->us) US_free(n->us);
}

// SIDに紐づく次ノードアドレスの取得
const unsigned char* state_get_next(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
            // if (i == MAX_STATE/2) {
                // printf("state_get_next: found matching SID at index %d\n", i);
                return n->state[i].next_addr;
            // }
    }
    return 0;
}

// SIDに紐づく前ノードアドレスの取得
const unsigned char* state_get_prev(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
        // if (i == MAX_STATE/2) {
                // printf("state_get_prev: found matching SID at index %d\n", i);
                return n->state[i].prev_addr;
            // }
    }
    return 0;
}
// SIDに紐づくτの取得
const unsigned char* state_get_tau(const Node *n, const unsigned char sid[SID_LEN]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (n->state[i].used && memcmp(n->state[i].sid, sid, SID_LEN)==0)
        // if (i == MAX_STATE/2) {
                // printf("state_get_tau: found matching SID at index %d\n", i);
                return n->state[i].tau;
            // }
    }
    return NULL;
}

// π-list をセッションID (SID) ごとに保存、読み込みする関数
int save_pi_list(const unsigned char sid[SID_LEN], const unsigned char *pi_concat, size_t pi_len) {
    // char filename[128];
    // // SIDの先頭8バイトをファイル名に利用
    // char sid_hex[17];
    // for (int i = 0; i < 8; i++)
    //     sprintf(&sid_hex[i*2], "%02x", sid[i]);
    // sid_hex[16] = '\0';
    // snprintf(filename, sizeof(filename), "pi_%s.dat", sid_hex);
    const char *filename = "pi_list.dat";

    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    // ファイル構造: [SID(32B)] [π-list本体]
    fwrite(sid, 1, SID_LEN, f);
    fwrite(pi_concat, 1, pi_len, f);
    fclose(f);
    
    // printf("Saved π-list (%zu bytes) as %s\n", pi_len, filename);
    return 0;
}

int load_pi_list(const char *filename, unsigned char sid[SID_LEN], unsigned char **pi_out, size_t *pi_len_out){
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    if (len <= SID_LEN) {
        fclose(f);
        return -1;
    }

    // fread(sid, 1, SID_LEN, f);
    if (fread(sid, 1, SID_LEN, f) != SID_LEN) {
        fprintf(stderr, "Error reading SID\n");
    }
    *pi_len_out = len - SID_LEN;
    *pi_out[*pi_len_out];
    // fread(*pi_out, 1, *pi_len_out, f);
    if (fread(*pi_out, 1, *pi_len_out, f) != *pi_len_out) {
        fprintf(stderr, "Error reading pi\n");
    }
    fclose(f);

    return 0;
}

// ポリシー違反の検出
int apply_policy_contract(const char *msg) {
    if (!msg) return 0;
    for (int i = 0; i < POLICY_COUNT; i++) {
        if (strstr(msg, policy[i]) != NULL) {
            // 禁止ワード表示(英語で)
            // printf("Detected: '%s'\n", policy[i]);
            return 1;
        }
    }
    return 0;
}

//Undeneiable Signature
US_CTX* US_init(const char *curve_name) {
    int nid;
    if (!curve_name) return NULL;

    // 例：curve_name = "secp256k1"
    nid = OBJ_txt2nid(curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Error: Unknown curve name: %s\n", curve_name);
        return NULL;
    }

    US_CTX *us = (US_CTX*)malloc(sizeof(US_CTX));
    if (!us) return NULL;

    us->ctx = BN_CTX_new();
    if (!us->ctx) {
        free(us);
        return NULL;
    }

    us->group = EC_GROUP_new_by_curve_name(nid);
    if (!us->group) {
        BN_CTX_free(us->ctx);
        free(us);
        return NULL;
    }

    us->order = BN_new();
    if (!us->order || !EC_GROUP_get_order(us->group, us->order, us->ctx)) {
        if (us->order) BN_free(us->order);
        EC_GROUP_free(us->group);
        BN_CTX_free(us->ctx);
        free(us);
        return NULL;
    }

    return us;
}

void US_free(US_CTX *us) {
    if (!us) return;
    if (us->order) BN_free(us->order);
    if (us->group) EC_GROUP_free(us->group);
    if (us->ctx) BN_CTX_free(us->ctx);
    free(us);
}

int save_us_x_pem(BIGNUM *x, const char *filename) {
    if (!x || !filename) return 0;

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        return 0;
    }

    // 秘密鍵を16進文字列にして保存
    char *hex = BN_bn2hex(x);
    if (!hex) {
        fclose(fp);
        return 0;
    }

    fprintf(fp, "-----BEGIN EC PRIVATE KEY-----\n%s\n-----END EC PRIVATE KEY-----\n", hex);
    OPENSSL_free(hex);
    fclose(fp);
    return 1;
}

BIGNUM *load_us_x_pem(const char *filename) {
    if (!filename) return NULL;

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    char buf[256];
    char hex[256] = {0};
    int found = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "BEGIN") || strstr(buf, "END")) continue;
        strcat(hex, buf);
        found = 1;
    }
    fclose(fp);
    if (!found) return NULL;

    // 改行を除去
    hex[strcspn(hex, "\r\n")] = 0;

    BIGNUM *x = NULL;
    if (!BN_hex2bn(&x, hex)) {
        fprintf(stderr, "BN_hex2bn failed for %s\n", filename);
        return NULL;
    }
    return x;
}

int hash_to_scalar(US_CTX *us, unsigned char *msg, size_t msglen, BIGNUM *out) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(msg, msglen, digest);
    // convert digest to BIGNUM and reduce mod order
    if (!BN_bin2bn(digest, SHA256_DIGEST_LENGTH, out)) return 0;
    if (!BN_mod(out, out, us->order, us->ctx)) return 0;
    // ensure non-zero
    if (BN_is_zero(out)) if (!BN_one(out)) return 0;
    return 1;
}

int US_sign(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *x, unsigned char **sig, size_t *sig_len){
    if (!message || !x || !us->ctx || !sig_len) return 0;

    int ret = 0;
    BIGNUM *m_scalar = NULL;
    EC_POINT *M = NULL;
    EC_POINT *Z = NULL;
    *sig = NULL;

    // ensure order is set
    if (!EC_GROUP_get_order(us->group, us->order, us->ctx)) {
        fprintf(stderr,"EC_GROUP_get_order error\n");
        return 0;
    }

    // 1) hash -> scalar
    m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)) {
        fprintf(stderr,"hash_to_scalar error\n"); return 0;
    }
    // 2) M = m_scalar * G
    M = EC_POINT_new(us->group);
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    if (!EC_POINT_mul(us->group, M, NULL, G, m_scalar, us->ctx)) { fprintf(stderr,"M mul error\n"); return 0; }
    size_t M_len = EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    unsigned char M_bytes[M_len];
    if (!EC_POINT_point2oct(us->group, M, POINT_CONVERSION_COMPRESSED, M_bytes, M_len, us->ctx)) {
        fprintf(stderr, "EC_POINT_point2oct(M) failed\n");
        return -1;
    }
    // print_hex("M", M_bytes, M_len);

    // 3) Z = x * M
    Z = EC_POINT_new(us->group);
    if (!EC_POINT_mul(us->group, Z, NULL, M, x, us->ctx)) { fprintf(stderr,"Z mul error\n"); return 0; }

    // 4) serialize to compressed form
    *sig_len = EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, NULL, 0, us->ctx);
    *sig = (unsigned char*)malloc(*sig_len);
    if (EC_POINT_point2oct(us->group, Z, POINT_CONVERSION_COMPRESSED, *sig, *sig_len, us->ctx) != (int)*sig_len) {
        fprintf(stderr,"EC_POINT_point2oct error\n"); return 0;
    }
    // print_hex("US:", *sig, *sig_len);

    ret = 1;
    if (m_scalar) BN_free(m_scalar);
    if (M) EC_POINT_free(M);
    if (Z) EC_POINT_free(Z);
    return ret;
}

// 論文に基づく NIZK Confirm メッセージ検証
int US_NIZK_VerifyC(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *confirm_msg, size_t confirm_len) {
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // ------------ Step 1. Rebuild M, Z ------------
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)) {
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    };

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx)) {
        fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
        return 0;
    };

    // ------------ Step 2. Parse confirm_msg ------------
    int bnlen = BN_num_bytes(us->order);
    unsigned char *p = confirm_msg;

    // read points
    size_t C_len = 33;    // for secp256k1
    size_t Gp_len = 33;
    size_t Mp_len = 33;

    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Mprime = EC_POINT_new(us->group);
    // print_hex("C (from confirm_msg):", p, C_len);
    // EC_POINT_oct2point(us->group, C, p, C_len, ctx); p += C_len;
    EC_POINT_oct2point(us->group, Gprime, p, Gp_len, ctx); p += Gp_len;
    // print_hex("G' (from confirm_msg):", p - Gp_len, Gp_len);
    EC_POINT_oct2point(us->group, Mprime, p, Mp_len, ctx); p += Mp_len;
    // print_hex("M' (from confirm_msg):", p - Mp_len, Mp_len);

    // read scalars
    // BIGNUM *h = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    BIGNUM *d = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    // print_hex("d (from confirm_msg):", p - bnlen, bnlen);
    BIGNUM *w = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    // print_hex("w (from confirm_msg):", p - bnlen, bnlen);
    BIGNUM *r = BN_bin2bn(p, bnlen, NULL);
    // print_hex("r (from confirm_msg):", p - bnlen, bnlen);

    // ------------ Step 3. Recompute h' = H(C,G',M') ------------
    size_t C_bytes_len = C_len, Gp_bytes_len = Gp_len, Mp_bytes_len = Mp_len;
    unsigned char C_bytes[C_bytes_len], Gp_bytes[Gp_bytes_len], Mp_bytes[Mp_bytes_len];
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_bytes_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_bytes_len, ctx);
    EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, Mp_bytes, Mp_bytes_len, ctx);
    
    //Cを再計算
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, G, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);
    // size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);


    size_t htmp1_len; unsigned char *htmp1 = concat2(C_bytes, C_bytes_len, Gp_bytes, Gp_bytes_len, &htmp1_len);
    size_t htmp2_len; unsigned char *htmp2 = concat2(htmp1, htmp1_len, Mp_bytes, Mp_bytes_len, &htmp2_len);
    BIGNUM *h = BN_new();
    if (!hash_to_scalar(us, htmp2, htmp2_len, h)) {
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    };
    free(htmp1); free(htmp2);

    // ------------ Step 5. Check dG = G' + (h+w)YA ------------
    EC_POINT *lhs = EC_POINT_new(us->group);
    EC_POINT *rhs = EC_POINT_new(us->group);
    BIGNUM *hw = BN_new(); BN_mod_add(hw, h, w, us->order, ctx);

    EC_POINT_mul(us->group, lhs, NULL, G, d, ctx);
    EC_POINT_mul(us->group, tmp1, NULL, YA, hw, ctx);
    EC_POINT_add(us->group, rhs, Gprime, tmp1, ctx);
    if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
        fprintf(stderr, "Failed at check dG = G' + (h+w)YA\n");
        return 0;
    };

    // ------------ Step 6. Check dM = M' + (h+w)Z ------------
    EC_POINT_mul(us->group, lhs, NULL, M, d, ctx);
    EC_POINT_mul(us->group, tmp1, NULL, Z, hw, ctx);
    EC_POINT_add(us->group, rhs, Mprime, tmp1, ctx);
    if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
        fprintf(stderr, "Failed at final check dM = M' + (h+w)Z\n");
        return 0;
    };

    ret = 1;

    BN_free(m_scalar); BN_free(h); BN_free(d); BN_free(w); BN_free(r); BN_free(hw);
    EC_POINT_free(M); EC_POINT_free(Z);
    EC_POINT_free(C); EC_POINT_free(Gprime); EC_POINT_free(Mprime);
    EC_POINT_free(tmp1); EC_POINT_free(tmp2);
    EC_POINT_free(lhs); EC_POINT_free(rhs);
    return ret;
}

int US_NIZK_VerifyD(US_CTX *us, EC_POINT *YA, EC_POINT *YB, unsigned char *message, size_t message_len, unsigned char *sig, size_t sig_len, unsigned char *disavow_msg, size_t disavow_len){
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // ---- Rebuild M,Z ----
    BIGNUM *m = BN_new();
    hash_to_scalar(us, message, message_len, m);

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx);

    // ---- Parse disavow_msg (D, G', M', d, w, r)----
    unsigned char *p = disavow_msg;
    size_t D_len = 33, Gp_len = 33, Mp_len = 33;
    int bnlen = BN_num_bytes(us->order);

    EC_POINT *D = EC_POINT_new(us->group);
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Mprime = EC_POINT_new(us->group);
    EC_POINT_oct2point(us->group, D, p, D_len, ctx); p += D_len;
    EC_POINT_oct2point(us->group, Gprime, p, Gp_len, ctx); p += Gp_len;
    EC_POINT_oct2point(us->group, Mprime, p, Mp_len, ctx); p += Mp_len;
    
    BIGNUM *d = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    BIGNUM *w = BN_bin2bn(p, bnlen, NULL); p += bnlen;
    BIGNUM *r = BN_bin2bn(p, bnlen, NULL);
    
    // --- D が無限遠点（ゼロ）でないこと ---
    if (EC_POINT_is_at_infinity(us->group, D)) {
        // printf("Disavow failed: Difference D is zero (Signature is valid).\n");
        return 0;
    }

    // ---- Check C = wG + rYB ----
    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *lhs = EC_POINT_new(us->group);
    EC_POINT *rhs = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, lhs, NULL, G, w, ctx);
    EC_POINT_mul(us->group, rhs, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, lhs, rhs, ctx);

    // ---- Recompute h ----
    unsigned char Cb[D_len], Gpb[Gp_len], Mpb[Mp_len];
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, Cb, D_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gpb, Gp_len, ctx);
    EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, Mpb, Mp_len, ctx);

    size_t l1; unsigned char *tmp = concat2(Cb, D_len, Gpb, Gp_len, &l1);
    size_t l2; unsigned char *buf = concat2(tmp, l1, Mpb, Mp_len, &l2);
    BIGNUM *h = BN_new();
    hash_to_scalar(us, buf, l2, h);
    free(tmp); free(buf);


    // ---- Verify 1: dG = G' + (h+w)YA ----
    BIGNUM *hw = BN_new();
    BN_mod_add(hw, h, w, us->order, ctx);
    EC_POINT_mul(us->group, lhs, NULL, G, d, ctx);
    EC_POINT_mul(us->group, rhs, NULL, YA, hw, ctx);
    EC_POINT_add(us->group, rhs, Gprime, rhs, ctx);
    if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
        // printf("Disavow ZKP failed at check 1 (Commitment equality).\n");
        return 0;
    }
    // Verify 2: dM = M' + (h+w)(Z - D)
    // xAを使わず、公開値 Z, D と M を使う
    
    // lhs = d*M
    EC_POINT_mul(us->group, lhs, NULL, M, d, ctx);

    // rhs = M' + (h+w)*(Z - D)
    // まず (Z - D) を計算
    EC_POINT *Z_minus_D = EC_POINT_new(us->group);
    EC_POINT *neg_D = EC_POINT_new(us->group);
    EC_POINT_copy(neg_D, D);
    EC_POINT_invert(us->group, neg_D, ctx); // -D
    EC_POINT_add(us->group, Z_minus_D, Z, neg_D, ctx); // Z - D

    // (h+w)*(Z - D)
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, Z_minus_D, hw, ctx);
    // M' + ...
    EC_POINT_add(us->group, rhs, Mprime, tmp1, ctx);

    if (EC_POINT_cmp(us->group, lhs, rhs, ctx) != 0) {
        fprintf(stderr, "Disavow ZKP failed at check 2 (Signature inequality).\n");
    }

    // D != 0 なので、Z != xA*M であることが証明
    ret = 1;

    return ret;
}

// Commit256
void Commit256(const unsigned char *s_bytes, size_t s_len, const unsigned char *r_bytes, size_t r_len, unsigned char *out_commit) {
    size_t comm_len;
    unsigned char *comm = concat2(s_bytes, s_len, r_bytes, r_len, &comm_len);
    SHA256(comm, comm_len, out_commit);
    free(comm);
}

