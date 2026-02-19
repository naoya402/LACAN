#include "common_func.h"
#include "TLS_func.h"



EVP_MD_CTX *mdctx1 = NULL;// 署名用
EVP_MD_CTX *mdctx2 = NULL;// 検証用

/* ======= 固定TLS鍵とIV (handshake省略) ======= */
const uint8_t fixed_tls_iv[12] = {
    0xf4, 0x83, 0x3e, 0x10, 0xa4, 0x38, 0xbf, 0x13, 0xaf, 0xb0, 0x1e, 0x8f
};
const uint8_t fixed_tls_key[32] = {
    0xc7, 0xb5, 0x68, 0x7a, 0xfb, 0xc2, 0xfc, 0x4f,
    0xc8, 0xf1, 0x15, 0xb0, 0x18, 0x0d, 0x9d, 0x26,
    0xf9, 0x2c, 0xf7, 0x46, 0xac, 0xbb, 0xd1, 0x20,
    0x61, 0x0e, 0xd7, 0x67, 0x39, 0xda, 0x7e, 0xbb
};

// MACとセッションの暗号化通信で用いる
static const uint8_t FIXED_IV[12] = {
    0xf4,0x83,0x3e,0x10,0xa4,0x38,0xbf,0x13,
    0xaf,0xb0,0x1e,0x8f
};
/* nonce counter: 接続ごとに別で良いので static に持つ（両端とも同様の扱いで） */
uint32_t nonce_counter = 1;

unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen) {
    *outlen = alen + blen;
    unsigned char *buf = (unsigned char*)malloc(*outlen);
    if (!buf) die("malloc failed");
    memcpy(buf, a, alen);
    memcpy(buf + alen, b, blen);
    return buf;
}

// AES-GCM暗号化
void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]) {
    // RAND_bytes(iv, IV_LEN);
    memcpy(iv, FIXED_IV, IV_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("cipher ctx");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("enc_init1");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) die("set_ivlen");
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) die("enc_init2");
    int len;
    if (EVP_EncryptUpdate(ctx, NULL, &len, sid, SID_LEN) != 1) die("aad");
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) die("enc_upd");
    int ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) die("enc_fin");
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) die("get_tag");
    EVP_CIPHER_CTX_free(ctx);
}

int aead_decrypt(const unsigned char key[KEY_LEN], const unsigned char *ct, size_t ct_len, const unsigned char sid[SID_LEN], const unsigned char iv[IV_LEN], const unsigned char tag[TAG_LEN], unsigned char *pt_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("cipher ctx");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("dec_init1");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) die("set_ivlen");
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) die("dec_init2");
    int len, ptlen;
    if (EVP_DecryptUpdate(ctx, NULL, &len, sid, SID_LEN) != 1) die("aad");
    if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) die("dec_upd");
    ptlen = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) die("set_tag");
    int ok = EVP_DecryptFinal_ex(ctx, pt_out + ptlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1; // 1=auth OK
}

// Ed25519 署名・検証
void sign_data(EVP_PKEY *sk, const unsigned char *data, size_t datalen, unsigned char *sig, size_t *siglen) {
    // EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    // if (!mdctx) die_ossl("EVP_MD_CTX_new");
    // if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, sk) <= 0)
    //     die_ossl("EVP_DigestSignInit");
    // if (EVP_DigestSign(mdctx, sig, siglen, data, datalen) <= 0)
    //     die_ossl("EVP_DigestSign");
    // EVP_MD_CTX_free(mdctx);
    if (!mdctx1) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestSign(mdctx1, sig, siglen, data, datalen) <= 0)
        die_ossl("EVP_DigestSign");
    // EVP_MD_CTX_free(mdctx1);
}

int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen) {
    // EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    // if (!mdctx) die_ossl("EVP_MD_CTX_new");
    // if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pk) <= 0)
    //     die_ossl("EVP_DigestVerifyInit");
    // int ok = EVP_DigestVerify(mdctx, sig, siglen, data, datalen);
    // EVP_MD_CTX_free(mdctx);
    // return ok == 1;
    if (!mdctx2) die_ossl("EVP_MD_CTX_new");
    int ok = EVP_DigestVerify(mdctx2, sig, siglen, data, datalen);
    // EVP_MD_CTX_free(mdctx);
    return ok == 1;
}
// ステート操作
void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char prev_addr[4], unsigned char next_addr[4], unsigned char nnext_addr[4], const unsigned char *tau, unsigned char rand_val[4]) {
        for (int i=0;i<MAX_STATE;i++) {
        if (!n->state[i].used) {
            n->state[i].used = 1;
            memcpy(n->state[i].sid, sid, SID_LEN);
            if (prev_addr) {
                memcpy(n->state[i].prev_addr, prev_addr, 4);
            }
            if (next_addr) {
                memcpy(n->state[i].next_addr, next_addr, 4);
            }
            if (nnext_addr) {
                memcpy(n->state[i].nnext_addr, nnext_addr, 4);
            }
            if (tau) {
                memcpy(n->state[i].tau, tau, SIG_LEN);
            }
            memcpy(n->state[i].rand_val, rand_val, 4);
            return;
        }
    }
    die("state full");
}

//========= オーバーレイ領域ヘッダ & ペイロード=========
// L2/L3 ダミーを埋めて最小 IPv4 ヘッダ(IHL = 5)作成
size_t write_l2l3_min(unsigned char *buf, size_t buf_cap) {
    if (buf_cap < ETH_LEN + sizeof(IPv4Hdr)) die("buf too small for L2/L3");
    EthHdr *eth = (EthHdr*)buf;
    memset(eth->dst, 0xff, 6);
    memset(eth->src, 0x11, 6);
    eth->ethertype = htons(0x0800);
    IPv4Hdr *ip = (IPv4Hdr*)(buf + ETH_LEN);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = (4<<4) | 5; // ver=4, IHL=5 => 20B
    ip->ttl = 64;
    ip->proto = 0xFD; // experimental
    return ETH_LEN + sizeof(IPv4Hdr);
}

// ======== オーバーレイのビルド/パース ========
size_t ipv4_header_len_bytes(const IPv4Hdr *ip) {
    return 4 * (ip->ver_ihl & 0x0F); // IHL * 4
}

size_t l3_overlay_offset(const unsigned char *l2) {
    const EthHdr *eth = (const EthHdr*)l2;
    (void)eth; // VLAN 無し前提。VLAN 対応は実運用で追加。
    const IPv4Hdr *ip = (const IPv4Hdr*)(l2 + ETH_LEN);
    return ETH_LEN + ipv4_header_len_bytes(ip); // 14 + IHL*4
}

// SETUP_REQ を 34B(=L3末) から書く
size_t build_overlay_setup_req(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    unsigned char *p = l2 + off; //現在の位置 ＋ L2L3オフセット
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;//ここまでで18B
    // print_hex("pkt.h.sid", pkt->h.sid, SID_LEN);
    // printf("R%d\n", pkt->h.idx);

   
    memcpy(p, pkt->h.seg_concat, MAX_SEG_CON); p += MAX_SEG_CON; // segリストは固定長
    // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
    if (pkt->h.idx == NODES){ // 最後のノードの処理後
        memcpy(p, pkt->h.dh_pk_concat, ROUTERS * PUB_LEN); p += ROUTERS * PUB_LEN; // DH公開鍵リストは固定長
        // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, ROUTERS * PUB_LEN);
    } else {
        memcpy(p, pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN); p += (pkt->h.idx - 1) * PUB_LEN; // DH公開鍵リストは固定長
        // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
    }
    memcpy(p, pkt->h.com_concat, (pkt->h.idx - 1) * COM_LEN); p += (pkt->h.idx - 1) * COM_LEN; // コミットメントリストは固定長
    // print_hex("pkt.h.com_concat", pkt->h.com_concat, (pkt->h.idx - 1) * COM_LEN);
    memcpy(p, pkt->h.pi_concat, pkt->h.idx * USIG_LEN); p += pkt->h.idx * USIG_LEN; // πリストは固定長(Sの生成した1個分確保)
    // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, pkt->h.idx * USIG_LEN);

    // ぺイロード
    memcpy(p, pkt->p.tau, SIG_LEN); p += SIG_LEN; //固定長で送る
    // print_hex("pkt.p.tau", pkt->p.tau, SIG_LEN);
    memcpy(p, pkt->p.v, 162); p += 162; //固定長で送る
    // print_hex("pkt.p.v", pkt->p.v, 162);
    memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN;
    // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
    // print_hex("Built SETUP_REQ", l2 + off, (size_t)(p - l2 - off));
    // グループ署名の署名長もpに乗せる
    uint32_t sig_len_n = htonl(pkt->p.sig_len);
    memcpy(p, &sig_len_n, sizeof(sig_len_n));
    // print_hex("pkt.p.sig_len", p, sizeof(sig_len_n));
    p += sizeof(sig_len_n);
    memcpy(p, pkt->p.sig_bytes, pkt->p.sig_len);p += pkt->p.sig_len;
    memcpy(p, pkt->p.ts, 4); p += 4;

    return (size_t)(p - l2 - off); // 書き終わったバイト位置
}

// DATA_TRANS を書く
size_t build_overlay_data_trans(unsigned char *l2, size_t cap, const Packet *pkt) {
    size_t off = l3_overlay_offset(l2);
    unsigned char *p = l2 + off;
    // ヘッダ
    memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;
    
    memcpy(p, pkt->h.acseg_concat, ROUTERS * ACSEG_LEN); p += ROUTERS * ACSEG_LEN;
    // print_hex("pkt.h.acseg_concat", pkt->h.acseg_concat, ROUTERS * ACSEG_LEN);
    // ぺイロード
    memcpy(p, pkt->p.iv, IV_LEN); p += IV_LEN;
    uint16_t n = htons(pkt->p.ct_len); memcpy(p, &n, 2); p += 2;
    memcpy(p, pkt->p.ct, pkt->p.ct_len); p += pkt->p.ct_len;
    memcpy(p, pkt->p.tag, TAG_LEN); p += TAG_LEN;
    return (size_t)(p - l2 - off);
}

// フレームからパケットをパース
int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt) {
    // L2/L3を読み飛ばす
    size_t l3end = l3_overlay_offset(frame);//34B
    if (l3end == 0) return -1;
    const unsigned char *buf = frame + l3end;
    const unsigned char *p = buf;
    size_t len = frame_len - l3end;
    if (len < SID_LEN + 1 + 1) return -1; // sid + status + dest
    
    //固定ヘッダ
    memcpy(pkt->h.sid, p, SID_LEN); p += SID_LEN;
    pkt->h.status = *p++;
    pkt->h.idx = *p++;
    // printf("pkt.h.idx: %d\n", pkt->h.idx);
    

    if (pkt->h.status == DATA_TRANS) {
        memcpy(pkt->h.acseg_concat, p, ROUTERS * ACSEG_LEN); p += ROUTERS * ACSEG_LEN;
        // print_hex("pkt.h.acseg_concat", pkt->h.acseg_concat, ROUTERS * ACSEG_LEN);
        // payload: IV + CT_LEN + CT + TAG
        if (p + IV_LEN > buf + len) return -1;
        memcpy(pkt->p.iv, p, IV_LEN); p += IV_LEN;
        pkt->p.ct_len = ntohs(*(uint16_t*)p); p += 2;
        if (p + pkt->p.ct_len > buf + len) return -1;
        memcpy(pkt->p.ct, p, pkt->p.ct_len); p += pkt->p.ct_len;
        if (p + TAG_LEN > buf + len) return -1;
        memcpy(pkt->p.tag, p, TAG_LEN); p += TAG_LEN;
    } else if (pkt->h.status == SETUP_REQ) {
        // seg_listをパース
        if (p + MAX_SEG_CON > buf + len) return -1;
        memcpy(pkt->h.seg_concat, p, MAX_SEG_CON); // segリストは固定長で受け取る
        // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
        p += MAX_SEG_CON;
        if (pkt->h.idx == NODES) {
            if (p + ROUTERS * PUB_LEN > buf + len) return -1;
            memcpy(pkt->h.dh_pk_concat, p, ROUTERS * PUB_LEN); // DH公開鍵リストはidxによる可変長で受け取る
            // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
            p += ROUTERS * PUB_LEN;
        } else {
            // dh_pk_list
            if (p + (pkt->h.idx - 1) * PUB_LEN > buf + len) return -1;
            memcpy(pkt->h.dh_pk_concat, p, (pkt->h.idx - 1) * PUB_LEN); // DH公開鍵リストはidxによる可変長で受け取る
            // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
            p += (pkt->h.idx - 1) * PUB_LEN;
        }
        // com_list
        if (p + (pkt->h.idx - 1) * COM_LEN > buf + len) return -1;
        memcpy(pkt->h.com_concat, p, (pkt->h.idx - 1) * COM_LEN); // コミットメントリストはidxによる可変長で受け取る
        // print_hex("pkt.h.com_concat", pkt->h.com_concat, (pkt->h.idx - 1) * COM_LEN);
        p += (pkt->h.idx - 1) * COM_LEN;
        //π_list
        if (p + pkt->h.idx * USIG_LEN > buf + len) return -1;
        memcpy(pkt->h.pi_concat, p, pkt->h.idx * USIG_LEN); // πリストはidxによる可変長で受け取る
        // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, pkt->h.idx * USIG_LEN);
        p += pkt->h.idx * USIG_LEN;
        // }

        //  τ + peer_pub
        if (p + SIG_LEN > buf + len) return -1;
        memcpy(pkt->p.tau, p, SIG_LEN); p += SIG_LEN;
        // print_hex("pkt.p.tau", pkt->p.tau, SIG_LEN);
        if (p + 162 > buf + len) return -1;
        memcpy(pkt->p.v, p, 162); p += 162;
        // print_hex("pkt.p.v", pkt->p.v, 162);
        if (p + PUB_LEN > buf + len) return -1;
        memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
        // print_hex("pkt.p.peer_pub", pkt->p.peer_pub, PUB_LEN);
        // グループ署名
        uint32_t sig_len_n;
        memcpy(&sig_len_n, p, sizeof(sig_len_n));
        pkt->p.sig_len = ntohl(sig_len_n);
        p += sizeof(sig_len_n);
        // printf ("sig_len: %lu\n", pkt->p.sig_len);
        if (p + pkt->p.sig_len > buf + len) return -1;
        memcpy(pkt->p.sig_bytes, p, pkt->p.sig_len); p += pkt->p.sig_len;
        // print_hex("pkt.p.sig_bytes", pkt->p.sig_bytes, pkt->p.sig_len);
        memcpy(pkt->p.ts, p, 4); p += 4;
    } else {
        return -1; // 未知のステータス
    }
    return 0;
}

// 修正したリレー処理（SETUP_REQの中継）
int router_handle_forward(unsigned char *frame, Node *nodes) {
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    
    Packet pkt;
    size_t frame_cap = MAX_FRAME;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    // printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    size_t m_len, mm_len, m2_len, mm2_len; //τ用
    size_t n_len, nn_len, n2_len, nn2_len; //π用
    // size_t cm_len; //コミットメント用
    size_t v_len; // πのNIZK用
    unsigned char *m = NULL, *mm = NULL, *n = NULL, *nn = NULL, *m2 = NULL, *mm2 = NULL, *n2 = NULL, *nn2 = NULL, *v = NULL;
    unsigned char tau[SIG_LEN];size_t tau_len = SIG_LEN;
    unsigned char rand_val[4];

    if (pkt.h.status != SETUP_REQ) { fprintf(stderr,"unexpected status\n"); return -1; }

    // unsigned char sid_chk[SID_LEN];
    // // print_hex("pkt.h.sid", pkt.h.sid, SID_LEN);
    // hash_sid_from_pub(pkt.p.peer_pub, sid_chk);
    // if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
    //     fprintf(stderr,"SID verify failed at R%d\n", idx);
    //     return -1;
    // }

    // 経路情報復号
    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    // print_hex("",pkt.p.peer_pub,PUB_LEN); // *********間違ってるパース失敗
    unsigned char sharec[SEC_LEN];
    derive_shared(me->dh_sk, nodes[0].dh_pk, sharec);
    memcpy(me->ki, sharec, KEY_LEN);
    // print_hex("ki", me->ki, KEY_LEN);

    size_t segoff = (me->id - 1) * (SEG_LEN + TAG_LEN + IV_LEN);
    const unsigned char *ci  = pkt.h.seg_concat + segoff;
    // print_hex("ci", ci, SEG_LEN);
    const unsigned char *tag = pkt.h.seg_concat + segoff + SEG_LEN;
    // print_hex("tag", tag, TAG_LEN);
    const unsigned char *iv  = pkt.h.seg_concat + segoff + SEG_LEN + TAG_LEN;
    // print_hex("iv", iv, IV_LEN);
    // 共有鍵 k_i で復号
    unsigned char plain[12];  // 復号結果を格納（12バイト＋α）
    if (!aead_decrypt(me->ki, ci, SEG_LEN, pkt.h.sid, iv, tag, plain))
        die("GCM auth fail (seg decrypt)");
    // printf("got plaintext: %s\n", plain);
    // print_hex("Decrypted segment", plain, 12);
    
    //復号結果を分割
    // 結果を分割: IPv4アドレス3つ分 (各4バイト)
    unsigned char prev_addr[4], next_addr[4], nnext_addr[4];
    memcpy(prev_addr,  plain,     4);
    memcpy(next_addr,  plain + 4, 4);
    memcpy(nnext_addr, plain + 8, 4);
    // printf("prev_addr: %u.%u.%u.%u\n", prev_addr[0], prev_addr[1], prev_addr[2], prev_addr[3]);
    // printf("next_addr: %u.%u.%u.%u\n", next_addr[0], next_addr[1], next_addr[2], next_addr[3]);
    // printf("nnext_addr: %u.%u.%u.%u\n", nnext_addr[0], nnext_addr[1], nnext_addr[2], nnext_addr[3]);


    //******アドレスからidxを引く
    int prev_idx = prev_addr[3];//get_node_idx(prev_addr, nodes);
    int next_idx = next_addr[3];//get_node_idx(next_addr, nodes);
    int nnext_idx = nnext_addr[3];//get_node_idx(nnext_addr, nodes);

    // 前ノードの τ_i-1 を検証
    // print_hex("Verifying tau from prev node", pkt.p.tau, SIG_LEN);
    m = concat2(pkt.h.sid, SID_LEN, me->addr, sizeof(me->addr), &m_len);
    mm = concat2(m, m_len, me->id != NODES-1 ? next_addr : prev_addr, sizeof(next_addr), &mm_len);
    // print_hex("mm", mm, mm_len);
    if (!verify_sig(nodes[prev_idx].pk, mm, mm_len, pkt.p.tau, SIG_LEN)) {//pkt.p.tau_len)) {
        fprintf(stderr, "Verify τ%d failed\n", prev_idx);
        free(m);
        free(mm);
        return -1;
    }
    // printf("Verify τ%d success\n", prev_idx);
    free(m);
    free(mm);
    
     // πのNIZKを検証
    // π_i-1を検証
    //pi_concatから前ノード分を取り出す
    unsigned char *pre_pi = (unsigned char *)malloc(USIG_LEN);
    memcpy(pre_pi, pkt.h.pi_concat + prev_idx * USIG_LEN, USIG_LEN);
    // print_hex("pre_pi", pre_pi, USIG_LEN);
    size_t pre_pi_len = USIG_LEN;
    //com_concatと取り出した残りのΠからnを生成
    n = concat2(pkt.h.com_concat, prev_idx * COM_LEN, pkt.h.pi_concat, prev_idx * USIG_LEN, &n_len);
    nn = concat2(pkt.h.dh_pk_concat, prev_idx * PUB_LEN, n, n_len, &nn_len);
    // print_hex("nn", nn, nn_len);

    v_len = 32 *3 + 33 * 2;
    int ver = US_NIZK_VerifyC(us, nodes[prev_idx].us_y, me->us_y, nn, nn_len, pre_pi, pre_pi_len, pkt.p.v, v_len);
    if (ver == 1) {
        // printf("NIZK Signature CONFIRMED.\n");
        // printf("Verify π%d success\n", prev_idx);
    } else if (ver == 0) {
        // printf("NIZK Signature NOT confirmed.\n");
        fprintf(stderr, "Verify π%d failed\n", prev_idx);
    }
    free(pre_pi);
    free(n);
    free(v);
    
    // レシーバを除く中継ノードの処理
    if (me->id != NODES-1) {
        // レシーバ用に鍵情報を格納
        unsigned char ki_pub[PUB_LEN];
        get_raw_pub(me->dh_sk, ki_pub);
        size_t koffset = (idx - 1) * PUB_LEN;
        
        memcpy(pkt.h.dh_pk_concat + koffset, ki_pub, PUB_LEN);
        // print_hex("DH PK concat", pkt.h.dh_pk_concat, (idx) * PUB_LEN);

        // コミットメント処理
        memset(rand_val, 0x11, sizeof(rand_val)); //便宜上乱数を任意の値に固定
        unsigned char commit[COM_LEN];
        Commit256(pkt.p.tau, SIG_LEN, rand_val, sizeof(rand_val), commit);
        size_t coffset = (idx - 1) * COM_LEN;

        if (coffset + COM_LEN > sizeof(pkt.h.com_concat)) {
            fprintf(stderr,"com_concat overflow at R%d\n", idx);
            // OPENSSL_free(pi);
            return -1;
        }
        memcpy(pkt.h.com_concat + coffset, commit, COM_LEN);
        // printf("C%d", idx);print_hex(" ", commit, COM_LEN);

        // π_i = Sign(sk_i, dh_pk_concat || com_concat || pi_concat) 
        n2 = concat2(pkt.h.com_concat, idx * COM_LEN, pkt.h.pi_concat, idx * USIG_LEN, &n2_len);
        nn2 = concat2(pkt.h.dh_pk_concat, idx * PUB_LEN , n2, n2_len, &nn2_len);
        // print_hex("nn2", nn2, nn2_len);
        unsigned char *USpi = NULL; size_t USpi_len;
        US_sign(us, nn2, nn2_len, me->us_x, &USpi, &USpi_len);
        size_t poffset = idx * USIG_LEN;
        // print_hex("USpi", USpi, USpi_len);

        if (poffset + USpi_len > sizeof(pkt.h.pi_concat)) {
            fprintf(stderr,"pi_concat overflow at R%d\n", idx);
            // OPENSSL_free(pi);
            return -1;
        }
        memcpy(pkt.h.pi_concat + poffset, USpi, USpi_len);
        // printf("π%d", idx);print_hex(" ", USpi, USpi_len);
        // print_hex("pi_concat", pkt.h.pi_concat, MAX_PI);

        // 次ホップの検証するvを生成
        size_t v2_len;
        unsigned char *v2 = NULL;//(unsigned char *)malloc(32 *3 + 33 * 2);
        int ver = US_NIZK_Confirm(us, nn2, nn2_len, me->us_x, nodes[next_idx].us_y, USpi, USpi_len, &v2, &v2_len);
        // print_hex("v2", v2, v2_len);

        memcpy(pkt.p.v, v2, v2_len);
        free(v2);
        free(n2);

        // τ_i = Sign(sk_i, sid||next_addr||nnext_addr)
        m2 = concat2(pkt.h.sid, SID_LEN, next_addr, sizeof(next_addr), &m2_len);
        mm2 = concat2(m2, m2_len, nnext_addr, sizeof(nnext_addr), &mm2_len);
        // print_hex("mm2", mm2, mm2_len);
        sign_data(me->sk, mm2, mm2_len, tau, &tau_len);
        free(m2);
        free(mm2);
        if (tau_len > SIG_LEN) { 
            // OPENSSL_free(tau); 
            fprintf(stderr,"tau_len too big\n"); return -1; }
        memcpy(pkt.p.tau, tau, tau_len);
        // printf("τ%d", idx); print_hex(" ", pkt.p.tau, tau_len);
        // OPENSSL_free(tau);
    }

    // 次のノードの位置を設定
    pkt.h.idx++;


    // ステート保存（prev=前ホップアドレス, next=次ホップアドレス or 自身）
    state_set(me, pkt.h.sid, prev_addr, next_addr, nnext_addr, pkt.p.tau, rand_val);

    // フレーム再構築
    size_t wire_len = build_overlay_setup_req(frame, frame_cap, &pkt);
    // printf("Forward frame wire_len=%zu com_list_len=%u pi_list_len=%u\n", wire_len, (idx-1) * COM_LEN, (idx-1) * USIG_LEN);
    return 0;
}

int router_handle_data_trans(unsigned char *frame, Node *nodes) {
    Packet pkt;
    size_t frame_cap = MAX_FRAME;
    if (parse_frame_to_pkt(frame, frame_cap, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    // printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    // printf("R%d -> ", idx);

    if (pkt.h.status != DATA_TRANS) { fprintf(stderr,"unexpected status\n"); return -1; }

    // 本来はstateから取得
    int next_addr = idx + 1; //state_get_next(me, pkt.h.sid);
    if (next_addr < 0) {
        die("no next hop in data forward");
    }

   // Sからのアカセグ検証
    unsigned char *acseg = (unsigned char *)malloc(ACSEG_LEN);
    unsigned int acseg_len;
    size_t offset = (idx - 1) * ACSEG_LEN;
    // print_hex("AC Plain", ac_plain2, ac_plain2_len);
    int gmac_result = aes_gmac(me->ki, KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, acseg, &acseg_len);
    // acseg_concat内の自身のacsegと比較
    // print_hex("Received ACSEG", pkt.h.acseg_concat, ROUTERS * ACSEG_LEN);
    if (memcmp(acseg, pkt.h.acseg_concat + offset, ACSEG_LEN) == 0) {
        // printf("R%d ACSEG match\n", idx);
    } else {
        printf("R%d ACSEG mismatch\n", idx);
        return -1;
    }
    free(acseg);

    // GMACでACSEG生成
    int gmac_result2 = aes_gmac(me->ki_R, KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, pkt.h.acseg_concat + offset, &acseg_len);
    if (gmac_result2 != 0) {
        fprintf(stderr,"GMAC failed at R%d\n", idx);
        return -1;
    }
    // printf("R%d ACSEG: ", idx); print_hex("", pkt.h.acseg_concat + offset, acseg_len);
    // print_hex("ACSEG", pkt.h.acseg_concat, ROUTERS * ACSEG_LEN);

    // ctのハッシュ値を計算
    unsigned char ct_hash[SHA256_DIGEST_LENGTH];
    SHA256(pkt.p.ct, pkt.p.ct_len, ct_hash);
    // print_hex("CT HASH", ct_hash, SHA256_DIGEST_LENGTH);
    // ************************ステートに記録

    pkt.h.idx++;
    
    size_t wire_len = build_overlay_data_trans(frame, frame_cap, &pkt);
    // printf("Data Trans frame wire_len=%zu \n", wire_len);
    return 0;
}

// 論文に基づく NIZK Confirm メッセージ生成
int US_NIZK_Confirm(US_CTX *us, unsigned char *message, size_t message_len,  BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **confirm_msg, size_t *confirm_len) {
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // ------------ Step 1. Recompute M, Z ------------
    BIGNUM *m_scalar = BN_new();
    if (!hash_to_scalar(us, message, message_len, m_scalar)){
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    }

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    if (!EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx)){
        fprintf(stderr, "Error: Failed to restore EC point from compressed signature.\n");
        return 0;
    };

    // ------------ Step 2. Sample w, r, t ------------
    BIGNUM *w = BN_new(), *r = BN_new(), *t = BN_new();
    BN_rand_range(w, us->order);
    BN_rand_range(r, us->order);
    BN_rand_range(t, us->order);
    
    // ------------ Step 3. Compute G', M' ------------
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Mprime = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, Gprime, NULL, G, t, ctx);
    EC_POINT_mul(us->group, Mprime, NULL, M, t, ctx);

    // ------------ Step 4. Compute C = w*G + r*YB ------------
    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, G, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);

    // ------------ Step 5. Compute h = H(C,G',M') ------------
    // serialize C, G', M'
    size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Gp_len = EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Mp_len = EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    unsigned char C_bytes[C_len], Gp_bytes[Gp_len], Mp_bytes[Mp_len];
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, C_bytes, C_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gp_bytes, Gp_len, ctx);
    EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, Mp_bytes, Mp_len, ctx);

    // concat for hash
    size_t htmp1_len; unsigned char *htmp1 = concat2(C_bytes, C_len, Gp_bytes, Gp_len, &htmp1_len);
    size_t htmp2_len; unsigned char *htmp2 = concat2(htmp1, htmp1_len, Mp_bytes, Mp_len, &htmp2_len);
    BIGNUM *h = BN_new();
    if (!hash_to_scalar(us, htmp2, htmp2_len, h)){
        fprintf(stderr,"hash_to_scalar error\n");
        return 0;
    };
    free(htmp1); free(htmp2);

    // ------------ Step 6. Compute d = t + xA*(h+w) mod q ------------
    BIGNUM *d = BN_new();
    BIGNUM *hw = BN_new(); // (h+w)
    BN_mod_add(hw, h, w, us->order, ctx);
    BN_mod_mul(hw, hw, xA, us->order, ctx); // xA*(h+w)
    BN_mod_add(d, t, hw, us->order, ctx);

    // ------------ Step 7. Serialize confirm_msg ------------
    // Output: [G'||M'||d||w||r]
    int bnlen = BN_num_bytes(us->order);
    *confirm_len = Gp_len + Mp_len + 3 * bnlen;
    *confirm_msg = (unsigned char *)malloc(*confirm_len);
    unsigned char *p = *confirm_msg;

    memcpy(p, Gp_bytes, Gp_len); p += Gp_len;
    // print_hex("G'", Gp_bytes, Gp_len);
    memcpy(p, Mp_bytes, Mp_len); p += Mp_len;
    // print_hex("M'", Mp_bytes, Mp_len);
    // BN_bn2binpad(h, p, bnlen); p += bnlen;
    BN_bn2binpad(d, p, bnlen); p += bnlen;
    // print_hex("d", p - bnlen, bnlen);
    BN_bn2binpad(w, p, bnlen); p += bnlen;
    // print_hex("w", p - bnlen, bnlen);
    BN_bn2binpad(r, p, bnlen); p += bnlen;
    // print_hex("r", p - bnlen, bnlen);

    // print_hex("US NIZK Confirm Msg:", *confirm_msg, *confirm_len);
    // printf("confirm_len: %zu\n", *confirm_len);

    ret = 1;

    BN_free(m_scalar); BN_free(w); BN_free(r); BN_free(t);
    BN_free(h); BN_free(d); BN_free(hw);
    EC_POINT_free(M); EC_POINT_free(Z);
    EC_POINT_free(Gprime); EC_POINT_free(Mprime); EC_POINT_free(C);
    EC_POINT_free(tmp1); EC_POINT_free(tmp2);
    return ret;
}

int US_NIZK_Disavow(US_CTX *us, unsigned char *message, size_t message_len, BIGNUM *xA, EC_POINT *YB, unsigned char *sig, size_t sig_len, unsigned char **disavow_msg, size_t *disavow_len){
    BN_CTX *ctx = us->ctx;
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    int ret = 0;

    // ---- Step 1. Recompute M, Z ----
    BIGNUM *m_scalar = BN_new();
    hash_to_scalar(us, message, message_len, m_scalar);

    EC_POINT *M = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, M, NULL, G, m_scalar, ctx);

    EC_POINT *Z = EC_POINT_new(us->group);
    EC_POINT_oct2point(us->group, Z, sig, sig_len, ctx);

    // ---- Step 2. D = Z - xA*M ----
    EC_POINT *D = EC_POINT_new(us->group);
    EC_POINT *xM = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, xM, NULL, M, xA, ctx);

    EC_POINT *neg_xM = EC_POINT_new(us->group);
    EC_POINT_copy(neg_xM, xM);
    EC_POINT_invert(us->group, neg_xM, ctx); // -xM
    EC_POINT_add(us->group, D, Z, neg_xM, ctx); // D = Z - xM
    EC_POINT_free(neg_xM);
    EC_POINT_point2oct(us->group, D, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);

    // ---- Step 3. Sample w,r,t ----
    BIGNUM *w = BN_new(), *r = BN_new(), *t = BN_new();
    BN_rand_range(w, us->order);
    BN_rand_range(r, us->order);
    BN_rand_range(t, us->order);

    // ---- Step 4. Compute G', D' ----
    EC_POINT *Gprime = EC_POINT_new(us->group);
    EC_POINT *Mprime = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, Gprime, NULL, G, t, ctx);
    EC_POINT_mul(us->group, Mprime, NULL, M, t, ctx);
    // EC_POINT_mul(us->group, Dprime, NULL, D, t, ctx);

    // ---- Step 5. Compute C = wG + rYB ----
    EC_POINT *C = EC_POINT_new(us->group);
    EC_POINT *tmp1 = EC_POINT_new(us->group);
    EC_POINT *tmp2 = EC_POINT_new(us->group);
    EC_POINT_mul(us->group, tmp1, NULL, G, w, ctx);
    EC_POINT_mul(us->group, tmp2, NULL, YB, r, ctx);
    EC_POINT_add(us->group, C, tmp1, tmp2, ctx);

    // ---- Step 6. h = H(C,G',M') ----
    size_t D_len = EC_POINT_point2oct(us->group, D, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t C_len = EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Gp_len = EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    size_t Mp_len = EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);

    unsigned char Db[D_len],Cb[C_len], Gpb[Gp_len], Mpb[Mp_len];
    EC_POINT_point2oct(us->group, D, POINT_CONVERSION_COMPRESSED, Db, D_len, ctx);
    EC_POINT_point2oct(us->group, C, POINT_CONVERSION_COMPRESSED, Cb, C_len, ctx);
    EC_POINT_point2oct(us->group, Gprime, POINT_CONVERSION_COMPRESSED, Gpb, Gp_len, ctx);
    EC_POINT_point2oct(us->group, Mprime, POINT_CONVERSION_COMPRESSED, Mpb, Mp_len, ctx);

    size_t l1; unsigned char *tmp = concat2(Cb, C_len, Gpb, Gp_len, &l1);
    size_t l2; unsigned char *buf = concat2(tmp, l1, Mpb, Mp_len, &l2);
    BIGNUM *h = BN_new();
    hash_to_scalar(us, buf, l2, h);
    free(tmp); free(buf);

    // ---- Step 7. d = t + xA(h+w) ----
    BIGNUM *hw = BN_new();
    BIGNUM *d = BN_new();
    BN_mod_add(hw, h, w, us->order, ctx);
    BN_mod_mul(hw, hw, xA, us->order, ctx);
    BN_mod_add(d, t, hw, us->order, ctx);

    // ---- Step 8. Serialize ----
    int bnlen = BN_num_bytes(us->order);
    *disavow_len = D_len + Gp_len + Mp_len + 3 * bnlen;
    *disavow_msg = (unsigned char*)malloc(*disavow_len);
    unsigned char *p = *disavow_msg;

    memcpy(p, Db, D_len); p += D_len;
    memcpy(p, Gpb, Gp_len); p += Gp_len;
    memcpy(p, Mpb, Mp_len); p += Mp_len;
    BN_bn2binpad(d, p, bnlen); p += bnlen;
    BN_bn2binpad(w, p, bnlen); p += bnlen;
    BN_bn2binpad(r, p, bnlen);

    ret = 1;

    BN_free(m_scalar); BN_free(w); BN_free(r); BN_free(t);
    BN_free(h); BN_free(hw); BN_free(d);
    EC_POINT_free(M); EC_POINT_free(Z); EC_POINT_free(xM);
    EC_POINT_free(D); EC_POINT_free(Gprime); EC_POINT_free(Mprime);
    EC_POINT_free(C); EC_POINT_free(tmp1); EC_POINT_free(tmp2);
    return ret;
}

// TLS AES-256-GCM Encryption/Decryption
/* ヘルパ: fixed_iv の最後4バイトに counter を XOR してnonceを作る */
void build_nonce(uint8_t *nonce_out, uint32_t counter) {
    memcpy(nonce_out, fixed_tls_iv, sizeof(fixed_tls_iv));
    uint32_t be = htonl(counter);
    /* XOR into last 4 bytes */
    for (int i = 0; i < 4; i++) {
        nonce_out[8 + i] ^= ((uint8_t*)&be)[i];
    }
}
int tls_encrypt(const unsigned char *pt, int pt_len, unsigned char **out, int *out_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, clen;
    uint8_t nonce[12];
    uint8_t tag[TAG_LEN];

    *out = NULL; *out_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    build_nonce(nonce, nonce_counter);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL) != 1) ;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, fixed_tls_key, nonce) != 1);

    unsigned char *ct = (unsigned char*)malloc(pt_len);

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) { free(ct);}
    clen = len;

    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) { free(ct); }
    clen += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) { free(ct); }

    /* 出力 = ciphertext || tag */
    *out_len = clen + TAG_LEN;
    *out = (unsigned char*)malloc(*out_len);
    if (!*out) { free(ct);}
    memcpy(*out, ct, clen);
    memcpy(*out + clen, tag, TAG_LEN);
    free(ct);

    EVP_CIPHER_CTX_free(ctx);
    return 0;

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int tls_decrypt(const unsigned char *in, int in_len, unsigned char **out_pt, int *out_pt_len) {
    if (in_len < TAG_LEN) return -1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plen;
    int ctlen = in_len - TAG_LEN;
    const unsigned char *ct = in;
    const unsigned char *tag = in + ctlen;
    uint8_t nonce[12];

    *out_pt = NULL; *out_pt_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    build_nonce(nonce, nonce_counter);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL) != 1) ;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, fixed_tls_key, nonce) != 1) ;

    unsigned char *pt = (unsigned char*)malloc(ctlen);
    if (!pt) ;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) != 1) { free(pt);}
    plen = len;

    /* set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag) != 1) { free(pt);}

    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) { /* 認証失敗 */ free(pt);}
    plen += len;

    *out_pt = pt;
    *out_pt_len = plen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}
