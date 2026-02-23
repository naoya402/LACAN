#include <time.h>
#include <unistd.h>

#include "common_func.h"
#include "DPDK_func.h"
// #include "func.h"


// 経路設定フェーズの測定用
__thread uint64_t for_verify_tau_cycles = 0;
__thread uint64_t for_verify_pi_cycles = 0;
__thread uint64_t for_com_c_cycles = 0;
__thread uint64_t for_sign_pi_cycles = 0;
__thread uint64_t for_conf_v_cycles = 0;
__thread uint64_t for_sign_tau_cycles = 0;

//データ転送の測定用
__thread uint64_t datatrans_verify_acseg_cycles = 0;
__thread uint64_t datatrans_gen_acseg_cycles = 0;

__thread EVP_MD_CTX *mdctx1 = NULL;// 署名用
__thread EVP_MD_CTX *mdctx2 = NULL;// 検証用

static const uint8_t FIXED_IV[12] = {
    0xf4,0x83,0x3e,0x10,0xa4,0x38,0xbf,0x13,
    0xaf,0xb0,0x1e,0x8f
};

// バイト列連結
unsigned char* concat2(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t *outlen) {
    *outlen = alen + blen;
    unsigned char *buf = (unsigned char*)malloc(*outlen);
    if (!buf) die("malloc failed");
    rte_memcpy(buf, a, alen);
    rte_memcpy(buf + alen, b, blen);
    return buf;
}

// AES-GCM暗号化/復号
void aead_encrypt(const unsigned char key[KEY_LEN],const unsigned char *pt, size_t pt_len, const unsigned char sid[SID_LEN], unsigned char iv[IV_LEN], unsigned char *ct, unsigned char tag[TAG_LEN]) {
    // RAND_bytes(iv, IV_LEN);
    rte_memcpy(iv, FIXED_IV, IV_LEN);
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
    if (!mdctx1) die_ossl("EVP_MD_CTX_new");
    if (EVP_DigestSign(mdctx1, sig, siglen, data, datalen) <= 0)
        die_ossl("EVP_DigestSign");
    // EVP_MD_CTX_free(mdctx1);
}

int verify_sig(EVP_PKEY *pk, const unsigned char *data, size_t datalen, const unsigned char *sig, size_t siglen) {
    if (!mdctx2) die_ossl("EVP_MD_CTX_new");
    int ok = EVP_DigestVerify(mdctx2, sig, siglen, data, datalen);
    // EVP_MD_CTX_free(mdctx);
    return ok == 1;
}

// ステートのセット
void state_set(Node *n, const unsigned char sid[SID_LEN], unsigned char prev_addr[4], unsigned char next_addr[4], unsigned char *nnext_addr, const unsigned char *tau, unsigned char rand_val[4]) {
    for (int i=0;i<MAX_STATE;i++) {
        if (!n->state[i].used) {
            n->state[i].used = 1;
            rte_memcpy(n->state[i].sid, sid, SID_LEN);
            if (prev_addr) {
                rte_memcpy(n->state[i].prev_addr, prev_addr, 4);
            }
            if (next_addr) {
                rte_memcpy(n->state[i].next_addr, next_addr, 4);
            }
            if (nnext_addr) {
                rte_memcpy(n->state[i].nnext_addr, nnext_addr, 4);
            }
            if (tau) {
                rte_memcpy(n->state[i].tau, tau, SIG_LEN);
            }
            rte_memcpy(n->state[i].rand_val, rand_val, 4);
            return;
        }
    }
    die("state full");
}

// L2/L3ヘッダの末尾位置を返す/
size_t read_l2l3_min(const unsigned char *frame, size_t frame_len) {
    size_t l2len = sizeof(struct rte_ether_hdr);
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr*)(frame + l2len);

    // IPv4 header length (IHL フィールド, 32-bit word 単位)
    size_t iphdr_len = (ip->version_ihl & 0x0F) * 4;
    size_t l3end = l2len + iphdr_len;
    if (iphdr_len < 20) return 0; // IHL min
    if (frame_len < l3end) return 0; // 長さ不足
    return l3end;
}

// 経路設定フェーズのパケット を 34B(=L3末) から書く
size_t build_overlay_setup_req(struct rte_mbuf *mbuf, const Packet *pkt) {
    size_t off = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
    unsigned char *p = rte_pktmbuf_mtod_offset(mbuf, unsigned char*, off);
    unsigned char *buf = p;
    // ヘッダ
    rte_memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;//ここまでで18B
    rte_memcpy(p, pkt->h.seg_concat, MAX_SEG_CON); p += MAX_SEG_CON; // segリストは固定長
    // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
    if (pkt->h.idx == NODES){ // 最後のノードの処理後
        rte_memcpy(p, pkt->h.dh_pk_concat, ROUTERS * PUB_LEN); p += ROUTERS * PUB_LEN; // DH公開鍵リストは固定長
        // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, ROUTERS * PUB_LEN);
    } else {
        rte_memcpy(p, pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN); p += (pkt->h.idx - 1) * PUB_LEN; // DH公開鍵リストは固定長
        // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
    }
    rte_memcpy(p, pkt->h.com_concat, (pkt->h.idx - 1) * COM_LEN); p += (pkt->h.idx - 1) * COM_LEN; // コミットメントリストは固定長
    // print_hex("pkt.h.com_concat", pkt->h.com_concat, (pkt->h.idx - 1) * COM_LEN);
    rte_memcpy(p, pkt->h.pi_concat, pkt->h.idx * USIG_LEN); p += pkt->h.idx * USIG_LEN; // πリストは固定長(Sの生成した1個分確保)
    // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, pkt->h.idx * USIG_LEN);


    // ぺイロード
    rte_memcpy(p, pkt->p.tau, SIG_LEN); p += SIG_LEN; //固定長で送る
    rte_memcpy(p, pkt->p.v, 162); p += 162; //固定長で送る
    // print_hex("pkt.p.v", pkt->p.v, 162);
    rte_memcpy(p, pkt->p.peer_pub, PUB_LEN); p += PUB_LEN;

    // グループ署名
    uint32_t sig_len_n = htonl(pkt->p.sig_len);
    rte_memcpy(p, &sig_len_n, sizeof(sig_len_n));
    p += sizeof(sig_len_n);
    // printf("pkt.p.sig_len: %lu\n", pkt->p.sig_len);
    rte_memcpy(p, pkt->p.sig_bytes, pkt->p.sig_len);p += pkt->p.sig_len;
    // print_hex("pkt.p.sig_bytes", pkt->p.sig_bytes, pkt->p.sig_len);
    rte_memcpy(p, pkt->p.ts, 4); p += 4;

    // ここで全体 FRAME_SIZE に合わせる
    size_t total_len = FRAME_SIZE -16;
    mbuf->pkt_len  = total_len;
    mbuf->data_len = total_len;

    size_t need = (size_t)(p - buf);

    // 足りない分をゼロ埋め（padding）
    if (need < total_len) {
        size_t pad_len = total_len - need;
        memset(p, 0, pad_len);
    }

    // IPv4 total_length を更新（L3のみ）
    struct rte_ipv4_hdr *ip =rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
    uint16_t new_tot_len = sizeof(struct rte_ipv4_hdr) + (uint16_t)need - off;
    ip->total_length = rte_cpu_to_be_16(new_tot_len);

    return need;
}

// データ転送フェーズのパケット を 34B(=L3末) から書く
size_t build_overlay_data_trans(struct rte_mbuf *mbuf, const Packet *pkt) {
    size_t off = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
    unsigned char *p = rte_pktmbuf_mtod_offset(mbuf, unsigned char*, off);
    unsigned char *buf = p;
    // ヘッダ
    rte_memcpy(p, pkt->h.sid, SID_LEN); p += SID_LEN;
    *p++ = pkt->h.status;
    *p++ = pkt->h.idx;//18
    rte_memcpy(p, pkt->h.acseg_concat, ROUTERS * ACSEG_LEN); p += ROUTERS * ACSEG_LEN;
    // ぺイロード
    rte_memcpy(p, pkt->p.iv, IV_LEN); p += IV_LEN;
    uint16_t n = htons(pkt->p.ct_len); rte_memcpy(p, &n, 2); p += 2;
    rte_memcpy(p, pkt->p.ct, pkt->p.ct_len); p += pkt->p.ct_len;
    rte_memcpy(p, pkt->p.tag, TAG_LEN); p += TAG_LEN;

    // ここで全体 FRAME_SIZE に合わせる
    size_t total_len = FRAME_SIZE -16;
    mbuf->pkt_len  = total_len;
    mbuf->data_len = total_len;

    size_t need = (size_t)(p - buf);

    // 足りない分をゼロ埋め（padding）
    if (need < total_len) {
        size_t pad_len = total_len - need;
        memset(p, 0, pad_len);
    }

    // IPv4 total_length を更新（L3のみ）
    struct rte_ipv4_hdr *ip =rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
    uint16_t new_tot_len = sizeof(struct rte_ipv4_hdr) + (uint16_t)need - off;
    ip->total_length = rte_cpu_to_be_16(new_tot_len);

    return need;
}

// フレームからパケットをパース
int parse_frame_to_pkt(const unsigned char *frame, size_t frame_len, Packet *pkt) {
    // L2/L3を読み飛ばす
    size_t l3end = read_l2l3_min(frame, frame_len);
    if (l3end == 0) return -1;
    const unsigned char *buf = frame + l3end;
    const unsigned char *p = buf;
    size_t len = frame_len - l3end;
    if (len < SID_LEN + 1 + 1) return -1;
    
    //固定ヘッダ
    rte_memcpy(pkt->h.sid, p, SID_LEN); p += SID_LEN;
    // print_hex("Parse SID", pkt->h.sid, SID_LEN);
    pkt->h.status = *p++;
    pkt->h.idx = *p++;
    
    if (pkt->h.status == DATA_TRANS) {
        rte_memcpy(pkt->h.acseg_concat, p, ROUTERS * ACSEG_LEN); p += ROUTERS * ACSEG_LEN;
        // payload: IV + CT_LEN + CT + TAG
        if (p + 12 > buf + len) return -1;
        rte_memcpy(pkt->p.iv, p, 12); p += 12;
        pkt->p.ct_len = ntohs(*(uint16_t*)p); p += 2;
        if (p + pkt->p.ct_len > buf + len) return -1;
        rte_memcpy(pkt->p.ct, p, pkt->p.ct_len); p += pkt->p.ct_len;
        // print_hex("Parsed ct", pkt->p.ct, pkt->p.ct_len);
        if (p + 16 > buf + len) return -1;
        rte_memcpy(pkt->p.tag, p, 16); p += 16;
    }else if (pkt->h.status == SETUP_REQ) {
        // seg_listをパース
        if (p + MAX_SEG_CON > buf + len) return -1;
        rte_memcpy(pkt->h.seg_concat, p, MAX_SEG_CON); // segリストは固定長で受け取る
        // print_hex("pkt.h.seg_concat", pkt->h.seg_concat, MAX_SEG_CON);
        p += MAX_SEG_CON;
        if (pkt->h.idx == NODES) {
            if (p + ROUTERS * PUB_LEN > buf + len) return -1;
            rte_memcpy(pkt->h.dh_pk_concat, p, ROUTERS * PUB_LEN); // DH公開鍵リストはidxによる可変長で受け取る
            // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
            p += ROUTERS * PUB_LEN;
        } else {
            // dh_pk_list
            if (p + (pkt->h.idx - 1) * PUB_LEN > buf + len) return -1;
            rte_memcpy(pkt->h.dh_pk_concat, p, (pkt->h.idx - 1) * PUB_LEN); // DH公開鍵リストはidxによる可変長で受け取る
            // print_hex("pkt.h.dh_pk_concat", pkt->h.dh_pk_concat, (pkt->h.idx - 1) * PUB_LEN);
            p += (pkt->h.idx - 1) * PUB_LEN;
        }
        // com_list
        if (p + (pkt->h.idx - 1) * COM_LEN > buf + len) return -1;
        rte_memcpy(pkt->h.com_concat, p, (pkt->h.idx - 1) * COM_LEN); // コミットメントリストはidxによる可変長で受け取る
        // print_hex("pkt.h.com_concat", pkt->h.com_concat, (pkt->h.idx - 1) * COM_LEN);
        p += (pkt->h.idx - 1) * COM_LEN;
        //π_list
        if (p + pkt->h.idx * USIG_LEN > buf + len) return -1;
        rte_memcpy(pkt->h.pi_concat, p, pkt->h.idx * USIG_LEN); // πリストはidxによる可変長で受け取る
        // print_hex("pkt.h.pi_concat", pkt->h.pi_concat, pkt->h.idx * USIG_LEN);
        p += pkt->h.idx * USIG_LEN;

        //  τ + peer_pub
        if (p + SIG_LEN > buf + len) return -1;
        rte_memcpy(pkt->p.tau, p, SIG_LEN); p += SIG_LEN;
        // printf("Tau: "); print_hex("", pkt->p.tau, SIG_LEN);
        if (p + 162 > buf + len) return -1;
        rte_memcpy(pkt->p.v, p, 162); p += 162;
        if (p + PUB_LEN > buf + len) return -1;
        rte_memcpy(pkt->p.peer_pub, p, PUB_LEN); p += PUB_LEN;
        // グループ署名
        uint32_t sig_len_n;
        rte_memcpy(&sig_len_n, p, sizeof(sig_len_n));
        pkt->p.sig_len = ntohl(sig_len_n);
        p += sizeof(sig_len_n);
        // printf ("sig_len: %lu\n", pkt->p.sig_len);
        if (p + pkt->p.sig_len > buf + len) return -1;
        rte_memcpy(pkt->p.sig_bytes, p, pkt->p.sig_len); p += pkt->p.sig_len;
        // print_hex("pkt.p.sig_bytes", pkt->p.sig_bytes, pkt->p.sig_len)
        rte_memcpy(pkt->p.ts, p, 4); p += 4;
    } else {
        return -1; // 未知のステータス
    }
    return 0;
}

// 経路設定フェーズのリレー処理
int router_handle_forward(struct rte_mbuf *mbuf, Node *nodes) {
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
     uint64_t t_verify_tau = 0;
    uint64_t t_sign_pi = 0;
    uint64_t t_sign_tau = 0;
    uint64_t router_start_cycles = rte_rdtsc();
   // mbuf から生ポインタと長さを取得
    unsigned char *frame = rte_pktmbuf_mtod(mbuf, unsigned char*);
    size_t frame_len = mbuf->pkt_len;
    if (frame_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + SID_LEN) {
        fprintf(stderr, "router_handle_forward_mbuf: frame too small (%zu)\n", frame_len);
        return -1;
    }
    Packet pkt;
    if (parse_frame_to_pkt(frame, frame_len, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    // printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    size_t m_len, mm_len, m2_len, mm2_len;
    size_t n_len, nn_len, n2_len, nn2_len; //π用
    size_t v_len; // πのNIZK用
    unsigned char *m = NULL, *mm = NULL, *n = NULL, *nn = NULL, *m2 = NULL, *mm2 = NULL, *n2 = NULL, *nn2 = NULL, *v = NULL;
    unsigned char tau[SIG_LEN]; size_t tau_len = SIG_LEN;
    
    if (pkt.h.status != SETUP_REQ) { 
        // fprintf(stderr,"unexpected status\n"); 
        return -1; 
    }

    
    // size_t start_cycles = rte_rdtsc();
    //公開鍵のハッシュで確認
    // unsigned char sid_chk[SID_LEN];
    // hash_sid(pkt.p.peer_pub, sid_chk);
    // if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) {
    //     fprintf(stderr,"SID verify failed\n");
    //     return -1;
    // }

    // size_t end_cycles = rte_rdtsc();
    // printf("SID hash cycles: %lu\n", end_cycles - start_cycles);
    
    // 経路情報復号
    size_t start_cycles = rte_rdtsc();
    EVP_PKEY *C_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char sharec[SEC_LEN];
    derive_shared(me->dh_sk, C_pub, sharec);
    rte_memcpy(me->ki, sharec, KEY_LEN);
    // print_hex("ki", me->ki, KEY_LEN);
    
    size_t segoff = (idx - 1) * (SEG_LEN + TAG_LEN + IV_LEN);
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

    //復号結果を分割
    // 結果を分割: IPv4アドレス3つ分 (各4バイト)
    unsigned char prev_addr[4], next_addr[4], nnext_addr[4];
    rte_memcpy(prev_addr,  plain,     4);
    rte_memcpy(next_addr,  plain + 4, 4);
    rte_memcpy(nnext_addr, plain + 8, 4);
    // printf("prev_addr: %u.%u.%u.%u\n", prev_addr[0], prev_addr[1], prev_addr[2], prev_addr[3]);
    // printf("next_addr: %u.%u.%u.%u\n", next_addr[0], next_addr[1], next_addr[2], next_addr[3]);
    // printf("nnext_addr: %u.%u.%u.%u\n", nnext_addr[0], nnext_addr[1], nnext_addr[2], nnext_addr[3]);

    //アドレスからidxを引く(今回はアドレスの最後をidxにしている)
    int prev_idx = prev_addr[3];//get_node_idx(prev_addr, nodes);
    int next_idx = next_addr[3];//get_node_idx(next_addr, nodes);
    int nnext_idx = nnext_addr[3];//get_node_idx(nnext_addr, nodes);
    // printf("prev_idx: %d\n", prev_idx);
    size_t end_cycles = rte_rdtsc();
    uint64_t cycles = end_cycles - start_cycles;
    // printf("Segment decrypt cycles: %lu\n", cycles);

    // 前ノードの τ_i-1 を検証
    // print_hex("Verifying tau from prev node", pkt.p.tau, SIG_LEN);
    start_cycles = rte_rdtsc();
    m = concat2(pkt.h.sid, SID_LEN, me->addr, sizeof(me->addr), &m_len);
    mm = concat2(m, m_len, me->id != NODES-1 ? next_addr : prev_addr, sizeof(next_addr), &mm_len);
    if (!verify_sig(nodes[prev_idx].pk, mm, mm_len, pkt.p.tau, SIG_LEN)) {//pkt.p.tau_len)) {
        fprintf(stderr, "Verify τ%d failed\n", prev_idx);
        free(m);
        return -1;
    }
    // printf("Verify τ%d success\n", prev_idx);
    free(m);
    free(mm);
    end_cycles = rte_rdtsc();
    for_verify_tau_cycles += (end_cycles - start_cycles);

    // πのNIZKを検証
    // π_i-1を検証
    start_cycles = rte_rdtsc();
    //pi_concatから前ノード分を取り出す
    unsigned char *pre_pi = (unsigned char *)malloc(USIG_LEN);
    rte_memcpy(pre_pi, pkt.h.pi_concat + prev_idx * USIG_LEN, USIG_LEN);
    // print_hex("pi", pi, USIG_LEN);
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
    free(nn);
    free(v);
    end_cycles = rte_rdtsc();
    for_verify_pi_cycles += (end_cycles - start_cycles);

    // レシーバを除く中継ノードの処理
    if (me->id != NODES-1) {
        // レシーバ用に鍵情報を格納
        unsigned char ki_pub[PUB_LEN];
        get_raw_pub(me->dh_sk, ki_pub);
        size_t koffset = (idx - 1) * PUB_LEN;
        
        rte_memcpy(pkt.h.dh_pk_concat + koffset, ki_pub, PUB_LEN);
        // print_hex("DH PK concat", pkt.h.dh_pk_concat, (idx) * PUB_LEN);

        // N2以降ならπとコミットメントを生成
        // コミットメント処理
        start_cycles = rte_rdtsc();
        unsigned char rand_val[4];
        memset(rand_val, 0x11, sizeof(rand_val)); //便宜上乱数を任意の値に固定
        unsigned char commit[COM_LEN];
        Commit256(pkt.p.tau, SIG_LEN, rand_val, sizeof(rand_val), commit);
        end_cycles = rte_rdtsc();
        for_com_c_cycles += (end_cycles - start_cycles);
        size_t coffset = (idx - 1) * COM_LEN;
        if (coffset + COM_LEN > sizeof(pkt.h.com_concat)) {
            fprintf(stderr,"com_concat overflow at R%d\n", idx);
            // OPENSSL_free(pi);
            return -1;
        }
        rte_memcpy(pkt.h.com_concat + coffset, commit, COM_LEN);
        // printf("C%d", idx);print_hex(" ", commit, COM_LEN);

        // π_i = Sign(sk_i, dh_pk_concat || com_concat || pi_concat) 
        start_cycles = rte_rdtsc();
        n2 = concat2(pkt.h.com_concat, idx * COM_LEN, pkt.h.pi_concat, idx * USIG_LEN, &n2_len);
        // printf(pkt.p.ct_len > 0 ? "ct_len=%zu\n" : "ct_len=0\n", pkt.p.ct_len);
        nn2 = concat2(pkt.h.dh_pk_concat, idx * PUB_LEN, n2, n2_len, &nn2_len);
        // print_hex("nn2", nn2, nn2_len);
        unsigned char *USpi = NULL; size_t USpi_len;
        US_sign(us, nn2, nn2_len, me->us_x, &USpi, &USpi_len);
        end_cycles = rte_rdtsc();
        for_sign_pi_cycles += (end_cycles - start_cycles);
        size_t poffset = idx * USIG_LEN;

        if (poffset + USpi_len > sizeof(pkt.h.pi_concat)) {
            fprintf(stderr,"pi_concat overflow at R%d\n", idx);
            // OPENSSL_free(pi);
            return -1;
        }
        rte_memcpy(pkt.h.pi_concat + poffset, USpi, USpi_len);
        // printf("π%d", idx);print_hex(" ", USpi, USpi_len);
        // print_hex("pi_concat", pkt.h.pi_concat, MAX_PI);

        // 次ホップの検証するvを生成
        start_cycles = rte_rdtsc();
        size_t v2_len; unsigned char *v2 = NULL;
        int ver = US_NIZK_Confirm(us, nn2, nn2_len, me->us_x, nodes[next_idx].us_y, USpi, USpi_len, &v2, &v2_len);// 本来2つ目は次ノードの公開鍵
        if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
        // print_hex("v2", v2, v2_len);
        end_cycles = rte_rdtsc();
        for_conf_v_cycles += (end_cycles - start_cycles);

        rte_memcpy(pkt.p.v, v2, v2_len);
        free(v2);
        free(n2);

        // τ_i = Sign(sk_i, sid||next_addr||nnext_addr)
        start_cycles = rte_rdtsc();
        m2 = concat2(pkt.h.sid, SID_LEN, next_addr, sizeof(next_addr), &m2_len);
        mm2 = concat2(m2, m2_len, nnext_addr, sizeof(nnext_addr), &mm2_len);
        sign_data(me->sk, mm2, mm2_len, tau, &tau_len);
        free(m2);
        free(mm2);
        end_cycles = rte_rdtsc();
        for_sign_tau_cycles += (end_cycles - start_cycles);
        if (tau_len > SIG_LEN) { 
            // OPENSSL_free(tau); 
            fprintf(stderr,"tau_len too big\n"); return -1; }
        rte_memcpy(pkt.p.tau, tau, tau_len);
        // printf("τ%d", idx); print_hex(" ", pkt.p.tau, tau_len);
        // OPENSSL_free(tau);
    }

    // 次のノードの位置を設定
    pkt.h.idx++; //本来はインクリメントするが増えすぎるのでやめる

    // ステート保存（prev=前ホップアドレス, next=次ホップアドレス or 自身）
    // state_set(me, pkt.h.sid, prev_idx, next_idx, nnext_idx, pkt.p.tau, rand_val);

    // フレーム再構築
    size_t wire_len = build_overlay_setup_req(mbuf, &pkt);
    // printf("Forward frame wire_len=%zu com_list_len=%u pi_list_len=%u\n", wire_len, (idx) * COM_LEN, (idx) * USIG_LEN);
    uint64_t router_end_cycles = rte_rdtsc();
    // printf("R%d cycles: %lu\n", idx, router_end_cycles - router_start_cycles);
    return 0;
}

// データ転送フェーズのリレー処理
int router_handle_data_trans(struct rte_mbuf *mbuf, Node *nodes) {
    uint64_t router_start_cycles = rte_rdtsc();
   // mbuf から生ポインタと長さを取得
    unsigned char *frame = rte_pktmbuf_mtod(mbuf, unsigned char*);
    size_t frame_len = mbuf->pkt_len;
    if (frame_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + SID_LEN) {
        fprintf(stderr, "router_handle_data_trans_mbuf: frame too small (%zu)\n", frame_len);
        return -1;
    }
    Packet pkt;
    if (parse_frame_to_pkt(frame, frame_len, &pkt) != 0) {
        fprintf(stderr, "Router: parse failed\n");
        return -1;
    }
    int idx = pkt.h.idx;
    // printf("\n=== Node R%d ===\n", idx);
    Node *me = &nodes[idx];
    if (pkt.h.status != DATA_TRANS) { 
        // fprintf(stderr,"unexpected status\n"); 
        return -1; 
    }

    // ステートを見て転送先決める 本来はこの後宛先のアドレスに設定
    // print_hex("prev_addr", state_get_prev(me, pkt.h.sid), 4);
    unsigned char next_addr[4];
    rte_memcpy(next_addr, state_get_next(me, pkt.h.sid), 4); //4のはず
    int next_idx = next_addr[3];
    // printf("Next addr: %u.%u.%u.%u\n", next_addr[0], next_addr[1], next_addr[2], next_addr[3]);
    // printf("Next addr: %d\n", next_addr[3]);

    // Sからのアカセグ検証
    uint64_t start_cycles = rte_rdtsc();
    unsigned char acseg[ACSEG_LEN];
    unsigned int acseg_len;
    size_t offset = (idx - 1) * ACSEG_LEN;
    // print_hex("AC Plain", ac_plain2, ac_plain2_len);
    // print_hex("ct", pkt.p.ct, pkt.p.ct_len);
    int gmac_result = aes_gmac(me->ki, KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, acseg, &acseg_len);
    // acseg_concat内の自身のacsegと比較
    // print_hex("Received ACSEG", pkt.h.acseg_concat + offset, ACSEG_LEN);
    // print_hex("Computed ACSEG", acseg, ACSEG_LEN);
    if (memcmp(acseg, pkt.h.acseg_concat + offset, ACSEG_LEN) == 0) {
        // printf("R%d ACSEG match\n", idx);
    } else {
        printf("R%d ACSEG mismatch\n", idx);
        return -1;
    }
    // free(acseg);
    uint64_t end_cycles = rte_rdtsc();
    datatrans_verify_acseg_cycles += (end_cycles - start_cycles);

    start_cycles = rte_rdtsc();
    // GMACでACSEG生成
    int gmac_result2 = aes_gmac(me->ki_R, KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, pkt.h.acseg_concat + offset, &acseg_len);
    if (gmac_result2 != 0) {
        fprintf(stderr,"GMAC failed at R%d\n", idx);
        return -1;
    }
    // free(ac_plain);
    uint64_t end_cycles2 = rte_rdtsc();
    datatrans_gen_acseg_cycles += (end_cycles2 - start_cycles);
    // printf("R%d ACSEG: ", idx); print_hex("", pkt.h.acseg_concat + offset, acseg_len);
    // print_hex("ACSEG", pkt.h.acseg_concat, ROUTERS * ACSEG_LEN);

    // ctのハッシュ値を計算
    unsigned char ct_hash[SHA256_DIGEST_LENGTH];
    SHA256(pkt.p.ct, pkt.p.ct_len, ct_hash);
    // print_hex("CT HASH", ct_hash, SHA256_DIGEST_LENGTH);
    // ************************ステートに記録
    rte_memcpy(me->state[0].ct_hash, ct_hash, SHA256_DIGEST_LENGTH);

    // 次のノードの位置を設定
    pkt.h.idx++;
    // フレーム再構築
    size_t wire_len = build_overlay_data_trans(mbuf, &pkt);
    // printf("Data Trans frame wire_len=%zu\n", wire_len); 
    uint64_t router_end_cycles = rte_rdtsc();
    // printf("R%d cycles: %lu\n", idx, router_end_cycles - router_start_cycles);
    return 0;
}

//Undeneiable Signature
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

    // rte_memcpy(p, C_bytes, C_len); p += C_len;
    rte_memcpy(p, Gp_bytes, Gp_len); p += Gp_len;
    // print_hex("G'", Gp_bytes, Gp_len);
    rte_memcpy(p, Mp_bytes, Mp_len); p += Mp_len;
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

    rte_memcpy(p, Db, D_len); p += D_len;
    rte_memcpy(p, Gpb, Gp_len); p += Gp_len;
    rte_memcpy(p, Mpb, Mp_len); p += Mp_len;
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
