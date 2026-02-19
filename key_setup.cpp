#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctime>
#include <iostream>
#include <fstream>
#include <vector>


#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include "common_func.h"
#include "TLS_func.h"


// 事前の鍵準備コード
#define CHECK_RC(rc, msg) \
    do { if ((rc) != IOK) { fprintf(stderr, "ERROR %s: rc=%d\n", (msg), (rc)); exit(1);} } while(0)

int main(int argc, char *argv[]) {
    int rc;

    // DH鍵の準備
    EVP_PKEY *dh_sk = gen_x25519_keypair();
    save_ed25519_seckey_pem(dh_sk, "key_st/dh_sec.pem");
    printf("Generated and saved DH secret key\n");
    EVP_PKEY_free(dh_sk);

    // Ed25519鍵の準備
    EVP_PKEY *ed_sk = gen_ed25519_keypair();
    save_ed25519_seckey_pem(ed_sk, "key_st/ed25519_sec.pem");
    unsigned char pub[PUB_LEN];
    size_t publen = sizeof(pub);
    // if (EVP_PKEY_get_raw_public_key(ed_sk, pub, &publen) <= 0);
    //     die_ossl("EVP_PKEY_get_raw_public_key");
    EVP_PKEY_get_raw_public_key(ed_sk, pub, &publen);
    EVP_PKEY *ed_pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, publen);
    save_ed25519_pubkey_pem(ed_pk, "key_st/ed25519_pub.pem");
    printf("Generated and saved Ed25519 public key\n");
    EVP_PKEY_free(ed_sk);
    EVP_PKEY_free(ed_pk);

    // USの秘密値(鍵)の準備
    US_CTX *us = US_init("secp256k1");
    BIGNUM *us_x = BN_new();
    BN_rand_range(us_x, us->order);
    save_us_x_pem(us_x, "key_st/us_x.pem");  // 初回のみ保存
    // === us_x の値を出力 ===
    // char *us_x_hex = BN_bn2hex(us_x);
    // if (us_x_hex) {
    //     printf(" us_x = %s\n", us_x_hex);
    //     OPENSSL_free(us_x_hex);
    // } else {
    //     fprintf(stderr, "Failed to convert us_x to hex.\n");
    // }
    // us_x = BN_new();
    // BN_rand_range(us_x, us->order);
    printf("Generated US x value\n");
    BN_free(us_x);
    US_free(us);

    // 追跡可能署名の鍵準備
    rc = groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    CHECK_RC(rc, "groupsig_init");

    groupsig_key_t *grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
    groupsig_key_t *mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
    // char *cstr = groupsig_grp_key_to_string(grpkey);
    // printf("grpkey: %s\n", cstr);
    // free(cstr);
    // char *mgrkstr = groupsig_mgr_key_to_string(mgrkey);
    // printf("Loaded Manager Key:\n%s\n", mgrkstr);
    // free(mgrkstr);
    gml_t *gml = gml_init(GROUPSIG_KTY04_CODE);
    // crl_t *crl = crl_init(GROUPSIG_KTY04_CODE);
    // if (!grpkey || !mgrkey || !gml || !crl) {
    //     fprintf(stderr, "NULL returned in key/gml/crl init\n");
    //     return 1;
    // }

    // Setup (new group)
    rc = groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);
    CHECK_RC(rc, "groupsig_setup");

    // 鍵サイズの確認
    int gsize = groupsig_grp_key_get_size(grpkey);
    int msize = groupsig_mgr_key_get_size(mgrkey);
    // printf("grpkey size(meta): %d, mgrkey size(meta): %d\n", gsize, msize);

    //--- グループ鍵エクスポート ---
    byte_t *grp_bytes = NULL;
    uint32_t grp_size = 0;
    groupsig_grp_key_export(&grp_bytes, &grp_size, grpkey);

    std::ofstream fgrp("key_st/grpkey.pem", std::ios::binary);
    fgrp.write((char*)grp_bytes, grp_size);
    fgrp.close();
    printf("Generated grpkey (%d bytes)\n", grp_size);

    // --- マネージャ鍵エクスポート ---
    byte_t *mgr_bytes = NULL;
    uint32_t mgr_size = 0;
    groupsig_mgr_key_export(&mgr_bytes, &mgr_size, mgrkey);
    std::ofstream fmgr("key_st/mgrkey.pem", std::ios::binary);
    fmgr.write((char*)mgr_bytes, mgr_size);
    fmgr.close();
    printf("Generated mgrkey (%d bytes)\n", mgr_size);

    // --- Join ---
    groupsig_key_t *memkey = groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
    if (!memkey) { fprintf(stderr,"memkey init failed\n"); return 1; }

    message_t *m1 = NULL, *m2 = NULL;
    rc = groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
    CHECK_RC(rc, "groupsig_join_mem");
    // printf("m1 length=%lu\n", m1? m1->length : 0);

    rc = groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);
    CHECK_RC(rc, "groupsig_join_mgr");
    // printf("m2 length=%lu\n", m2? m2->length : 0);

    groupsig_key_t *final_memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, m2->bytes, m2->length);
    if (!final_memkey) { fprintf(stderr,"final_memkey import failed\n"); return 1; }

    //最終の鍵を保存
    byte_t *mem_bytes = NULL;
    uint32_t mem_size = 0;
    groupsig_mem_key_export(&mem_bytes, &mem_size, final_memkey);

    std::ofstream fmem("key_st/memkey.pem", std::ios::binary);
    fmem.write((char*)mem_bytes, mem_size);
    fmem.close();
    printf("Generated memkey (%d bytes)\n", mem_size);
    free(mem_bytes);

    // --- GML をファイルに保存 ---
    byte_t *gml_bytes = NULL;
    uint32_t gml_size = 0;
    gml_export(&gml_bytes, &gml_size, gml);

    std::ofstream fgml("key_st/gml.dat", std::ios::binary);
    fgml.write((char*)gml_bytes, gml_size);
    fgml.close();
    printf("Generated gml\n");
    free(gml_bytes);

    // リソース解放
    message_free(m1);
    message_free(m2);
    groupsig_mem_key_free(memkey);
    groupsig_mem_key_free(final_memkey);
    gml_free(gml);
    groupsig_grp_key_free(grpkey);
    groupsig_mgr_key_free(mgrkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);
}