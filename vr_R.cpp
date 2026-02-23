#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include "common_func.h"
#include "TLS_func.h"
#include "config.h"


uint64_t tg_sign_cycles = 0;
uint64_t sender_setup_cycles = 0;
uint64_t tg_verify_cycles = 0;
uint64_t receiver_setup_cycles = 0;

uint64_t sender_datatrans_cycles = 0;
uint64_t receiver_datatrans_cycles = 0;

uint64_t report_conf_v_cycles = 0;
uint64_t report_cycles = 0;

// 鍵をファイルから読み込み
groupsig_key_t *load_key_from_file(const char *path, uint8_t scheme, groupsig_key_t *(*import_func)(uint8_t, byte_t *, uint32_t)) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    byte_t *buf = (byte_t *)malloc(len);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    fread(buf, 1, len, f);
    fclose(f);

    groupsig_key_t *key = import_func(scheme, buf, len);
    free(buf);
    return key;
}

static const uint8_t FIXED_IV[12] = {
    0xf4,0x83,0x3e,0x10,0xa4,0x38,0xbf,0x13,
    0xaf,0xb0,0x1e,0x8f
};

unsigned char ts[4] = {0, 1, 2, 3};

int main(int argc, char *argv[]) {
    // int ret = rte_eal_init(argc, argv);
    // if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    // uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t tsc_hz = 2000000000; // 2GHz
//     // printf("======= 経路設定フェーズ =======");
//     // printf("\n===============================往路=================================");
//     // printf("=== R (Receiver) ===\n");

//     Node *nodes = (Node *)rte_malloc(NULL, sizeof(Node) * NODES, 0);
//    if (nodes == NULL) {
//       printf("Failed to allocate memory for nodes\n");
//       return -1;
//    }
    // === Node群の初期化 ===
    Node nodes[NODES];
    for (int i = 0; i < NODES; i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    EVP_PKEY *sk = load_seckey_pem("dh_sec.pem");
    // 公開鍵 raw を取得して SID を再計算
    unsigned char kC_pub[PUB_LEN];
    get_raw_pub(sk, kC_pub);
    unsigned char sid[SID_LEN];
    hash_sid(kC_pub, PUB_LEN, sid);
    // print_hex("SID (Receiver)", sid, SID_LEN);
    // 受信側で τ_ROUTERSを生成(復路の検証用&通報用)
    Node *nod = &nodes[ROUTERS];
    unsigned char t[SIG_LEN];
    size_t t_len = SIG_LEN, g_len, g2_len;
    unsigned char sta_next_addr[4], sta_nnext_addr[4];
    memcpy(sta_next_addr, nodes[ROUTERS + 1].addr, sizeof(sta_next_addr));
    memcpy(sta_nnext_addr, nod->addr, sizeof(sta_nnext_addr));
    // print_hex("sta_next_addr for τ_ROUTERS", sta_next_addr, 4);
    // print_hex("sta_nnext_addr for τ_ROUTERS", sta_nnext_addr, 4);
    // τ_ROUTERS用のデータ
    unsigned char *g = concat2(sid, SID_LEN, sta_next_addr, 4, &g_len);
    unsigned char *g2 = concat2(g, g_len, sta_nnext_addr, 4, &g2_len);
    // print_hex("g for τ_ROUTERS", g, g_len);
    sign_data(nod->sk, g2, g2_len, t, &t_len);
    free(g);
    free(g2);

    // τ0用のデータ
    unsigned char tau[SIG_LEN];
    size_t tau_len = SIG_LEN;
    size_t m_len, mm_len;
    unsigned char *m = NULL, *mm = NULL;

    printf("======= 経路設定フェーズ =======");
    printf("\n===============================往路=================================");
    // センダーSの処理
    printf("\n=== Node S(R0) ===\n");
    Packet pkt; 
    // k_C 公開鍵取り出し & SID=H(k_C)
    // unsigned char kC_pub[PUB_LEN];
    int idx = 0;
    Node *me = &nodes[idx];
    get_raw_pub(me->dh_sk, kC_pub);
    print_hex("kC_pub", kC_pub, PUB_LEN);

    //グループ署名生成
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);//groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);//groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
    groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);;//groupsig_mem_key_init(GROUPSIG_KTY04_CODE);
    // gml読み込み
    FILE *fgml = fopen("gml.dat", "rb");
    if (!fgml) die("fopen gml.dat");
    fseek(fgml, 0, SEEK_END);
    size_t gml_len = ftell(fgml);
    fseek(fgml, 0, SEEK_SET);
    unsigned char *gml_buf = (unsigned char *)malloc(gml_len);
    if (!gml_buf) die("malloc gml_buf");
    fread(gml_buf, 1, gml_len, fgml);
    fclose(fgml);
    gml_t *gml = gml_import(GROUPSIG_KTY04_CODE, gml_buf, gml_len);
    free(gml_buf);
    crl_t *crl = crl_init(GROUPSIG_KTY04_CODE);

    // Setup (new group)
    groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

    // printf("計測開始\n");
    // int pkt_count = 10;
    // for (int trial = 0; trial < pkt_count; trial++) {
        //pkt_countの桁が変わるごとに表示
        // if (trial % 100 == 0) {
        //     printf("Trial: %d\n", trial);
        // }
    uint64_t start_cycles = rte_rdtsc();
    uint64_t sender_start_cycles = rte_rdtsc();
    size_t tsconcat_len;
    unsigned char *tsconcat = concat2(kC_pub, PUB_LEN, ts, 4, &tsconcat_len);
    message_t *gsm = message_from_bytes(tsconcat, tsconcat_len);
    // message_t *gsm = message_from_bytes(kC_pub, PUB_LEN);
    // print_hex("gsm", gsm->bytes, gsm->length);
    groupsig_signature_t *sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
    groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);
    // uint8_t valid;
    // groupsig_verify(&valid, sig, gsm, grpkey);
    // printf("TGsig verification: %s\n", valid ? "valid" : "invalid");
    // char *strsig = groupsig_signature_to_string(sig);
    // printf("R: gsig: %s\n", strsig);
    // free(strsig);

    // // --- 署名をバイナリにエクスポート ---
    byte_t *sig_bytes = NULL;
    uint32_t sig_size = 0;
    groupsig_signature_export(&sig_bytes, &sig_size, sig);
    // printf("Exported signature length: %u bytes\n", sig_size);
    // print_hex("Exported signature", sig_bytes, sig_size);
    uint64_t end_cycles = rte_rdtsc();
    tg_sign_cycles += end_cycles - start_cycles;    

    // unsigned char* にキャスト（byte_t は typedef unsigned char）
    unsigned char *uc_sig = (unsigned char *)malloc(sig_size);
    memcpy(uc_sig, sig_bytes, sig_size);
    // print_hex("Group signature σ", uc_sig, sig_size);

    // --- SID 生成 ---
    hash_sid(kC_pub, PUB_LEN, pkt.h.sid);// 簡便のためSID=H(kC)固定
    // print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
    pkt.h.status = SETUP_REQ;

    // 各リレーの共有鍵 k_i を計算 & c_i を生成
    unsigned char sharenode[SEC_LEN];
    for (int i = 1; i < NODES; i++) {
        derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
        memcpy(me->k[i], sharenode, KEY_LEN);
        // print_hex("ki", me->k[i], KEY_LEN);

        // 前後ホップ (例: prev=i-1, next=i+1)
        unsigned char *prehop  = nodes[i-1].addr;
        unsigned char *nexthop = (i == NODES - 1) ? nodes[i].addr : nodes[i+1].addr;
        unsigned char *nnexthop = (i >= NODES - 2) ? nodes[i].addr : nodes[i+2].addr;
        // printf("nnexthop: %d.%d.%d.%d\n", nnexthop[0], nnexthop[1], nnexthop[2], nnexthop[3]);

        size_t p_len;
        unsigned char *p = concat2(prehop, 4, nexthop, 4, &p_len);
        size_t ap_len;
        unsigned char *ap = concat2(p, p_len, nnexthop, 4, &ap_len);
        
        unsigned char ci[SEG_LEN];
        unsigned char iv[IV_LEN], tag[TAG_LEN];//, ci[SEG_LEN];
        aead_encrypt(me->k[i], ap, ap_len, pkt.h.sid, iv, ci, tag);
        // print_hex("ci", ci, SEG_LEN);
        // print_hex("tag", tag, TAG_LEN);
        size_t offset = (size_t)((i-1) % (ROUTERS + 1)) * (SEG_LEN + TAG_LEN + IV_LEN);//ROUTERS + 1では経路長が漏洩するため適切な固定長(12など)にする

        // memcpy(pkt.h.seg_concat + offset, t2, t2_len);
        // printf("offset=%zu\n", offset);
        memcpy(pkt.h.seg_concat + offset, ci, SEG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN, tag, TAG_LEN);
        memcpy(pkt.h.seg_concat + offset + SEG_LEN + TAG_LEN, iv, IV_LEN);
        // print_hex("",pkt.h.seg_concat,MAX_SEG_CON);
        free(p);  free(ap);
        // free(t1); free(t2);
    }

    // print_hex("seg_concat", pkt.h.seg_concat, (ROUTERS + 1) * (SEG_LEN + TAG_LEN + IV_LEN));
    unsigned char next_addr[4], nnext_addr[4];
    memcpy(next_addr, nodes[1].addr, sizeof(next_addr));
    memcpy(nnext_addr, nodes[2].addr, sizeof(nnext_addr));
    // τ_0 = Sign(sk_0, sid || N1 || N2)を生成
    m = concat2(pkt.h.sid, SID_LEN, next_addr, sizeof(next_addr), &m_len);
    mm = concat2(m, m_len, nnext_addr, sizeof(nnext_addr), &mm_len);
    sign_data(me->sk, mm, mm_len, tau, &tau_len);
    free(m);
    free(mm);
    //センダーもπ0生成
    US_CTX *us = US_init("secp256k1");
    unsigned char *n2 = NULL, *nn2 = NULL;
    size_t n2_len, nn2_len;
    // π_i = Sign(sk_i, dh_pk_concat || com_concat || pi_concat) 
    n2 = concat2(pkt.h.com_concat, idx * COM_LEN, pkt.h.pi_concat, idx * USIG_LEN, &n2_len);//idx-1をidxに変える
    // print_hex("n2", n2, n2_len);
    nn2 = concat2(pkt.h.dh_pk_concat, idx * PUB_LEN, n2, n2_len, &nn2_len);
    // print_hex("nn2", nn2, nn2_len);
    unsigned char *USpi = NULL; size_t USpi_len;
    US_sign(us, nn2, nn2_len, me->us_x, &USpi, &USpi_len);
    size_t poffset = idx * USIG_LEN;
    // print_hex("USpi", USpi, USpi_len);

    if (poffset + USpi_len > sizeof(pkt.h.pi_concat)) {
        fprintf(stderr,"pi_concat overflow\n");
        // OPENSSL_free(pi);
        return -1;
    }
    memcpy(pkt.h.pi_concat + poffset, USpi, USpi_len);
    // 次ホップの検証するvを生成
    size_t v2_len; // sufficient size
    unsigned char *v2 = NULL;//(unsigned char *)malloc(32 *3 + 33 * 2);
    int ver = US_NIZK_Confirm(us, nn2, nn2_len, me->us_x, me->us_y, USpi, USpi_len, &v2, &v2_len);
    // print_hex("v2", v2, v2_len);

    //パケットにτを格納
    memcpy(pkt.p.tau, tau, tau_len);
    // print_hex("τ0", tau, tau_len);
    memcpy(pkt.p.v, v2, v2_len);
    memcpy(pkt.p.peer_pub, kC_pub, PUB_LEN); // P に k_C を格納
    // print_hex("pkt.p.peer_pub", pkt.p.peer_pub, PUB_LEN);
    pkt.p.sig_len = sig_size;
    memcpy(pkt.p.sig_bytes, sig_bytes, sig_size);
    // print_hex("sig_bytes", pkt.p.sig_bytes, pkt.p.sig_len);
    memcpy(pkt.p.ts, ts, 4);
    
    // 状態保存（prev=0, next=1 or self）
    unsigned char temp_rand[4] = {0x11, 0x11, 0x11, 0x11};
    state_set(me, pkt.h.sid, NULL, nodes[idx + 1].addr, nodes[idx + 2].addr, pkt.p.tau, temp_rand);

    // 次のノードの位置を設定
    pkt.h.idx = 1;

    // ==== メモリに L2/L3 + overlay(SETUP_REQ) を構築（送信用）====
    // 往路の送信フレームを作成
    unsigned char frame[MAX_FRAME]; 
    memset(frame, 0, sizeof(frame));
    write_l2l3_min(frame, sizeof(frame));
    size_t wire_len = build_overlay_setup_req(frame, sizeof(frame), &pkt);
    end_cycles = rte_rdtsc();
    // SID(36) + seg_list(40*5) + πリスト(0) + peer_pub(32) + τ(64) = 332B
    // printf("S sending SETUP_REQ (%zu bytes)\n", wire_len);
    sender_setup_cycles += end_cycles - sender_start_cycles;

    // 各リレーの処理
    for (int i = 1; i < NODES; i++) {
        if (router_handle_forward(frame, nodes) != 0) die("forward fail");
    }

    // レシーバRの処理=======ここから本来RPathsetup.cpp=========
    // printf("\n=== Node R(R%d) ===\n", NODES - 1);
    // Node *
    me = &nodes[NODES-1];
    // Packet pkt;

    uint64_t receiver_start_cycles = rte_rdtsc();
    if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
        fprintf(stderr, "R: parse failed\n");
        return -1;
    }

    // char *cstr = groupsig_grp_key_to_string(grpkey);
    // printf("grpkey: %s\n", cstr);
    // free(cstr);
    // print_hex("R received peer_pub", pkt.p.peer_pub, PUB_LEN);
    //　グループ署名の検証
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    size_t sig_len = pkt.p.sig_len;
    uint8_t valid;

    start_cycles = rte_rdtsc();
    tsconcat = concat2(pkt.p.peer_pub, PUB_LEN, pkt.p.ts, 4, &tsconcat_len);
    message_t *ppp = message_from_bytes(tsconcat, tsconcat_len);
    groupsig_signature_t *gsig = groupsig_signature_import(GROUPSIG_KTY04_CODE, pkt.p.sig_bytes, pkt.p.sig_len);
    groupsig_verify(&valid, gsig, ppp, grpkey);
    // printf("TGsig verification: %s\n", valid ? "valid" : "invalid");
    end_cycles = rte_rdtsc();
    tg_verify_cycles += end_cycles - start_cycles;
    groupsig_signature_free(gsig);
    message_free(ppp);

    
    // Rもkを計算
    EVP_PKEY *S_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char shared[SEC_LEN];
    derive_shared(me->dh_sk, S_pub, shared);
    EVP_PKEY_free(S_pub);
    memcpy(me->sess_key, shared, KEY_LEN);
    me->has_sess = 1;
    // print_hex("R derived k", me->sess_key, KEY_LEN);

    // Rとリレーの鍵交換
    for (int i = 1; i < NODES - 1; i++) {
        size_t offset = (i - 1) * PUB_LEN;
        EVP_PKEY *node_pub = import_x25519_pub(pkt.h.dh_pk_concat + offset);
        derive_shared(me->dh_sk, node_pub, sharenode);
        memcpy(me->k[i], sharenode, KEY_LEN);
        // print_hex("ki", me->k[i], KEY_LEN);
    }

    // C,Π,グループ署名を保存
    save_pi_list(pkt.h.sid, pkt.h.pi_concat, MAX_PI);
    unsigned char pi_concat[MAX_PI];
    // memcpy(pi_concat, pkt.h.pi_concat, MAX_PI);
    // print_hex("R saved pi_concat", pi_concat, MAX_PI);
    // printf("\n");
    end_cycles = rte_rdtsc();
    receiver_setup_cycles += end_cycles - receiver_start_cycles;

    // printf("\n===============================復路=================================\n");
    // 本来はリレーがRと鍵交換するのは復路だが便宜上ここで処理
    for (int i = 1; i < NODES - 1; i++) {
        // 共有鍵を計算
        Node *node = &nodes[i];
        derive_shared(node->dh_sk, nodes[NODES - 1].dh_pk, sharenode);
        // リレーiの状態に鍵を保存
        memcpy(node->ki_R, sharenode, KEY_LEN); // 復路用キーは k[ROUTERS + 1] に保存
        // printf("k%d ", i);
        // print_hex("derived ", node->k[i], KEY_LEN);
    }
    // Sもkを計算
    me = &nodes[0];
    EVP_PKEY *R_pub = import_x25519_pub(pkt.p.peer_pub);
    unsigned char kC_shared[SEC_LEN];
    derive_shared(me->dh_sk, R_pub, kC_shared);
    EVP_PKEY_free(R_pub);

    memcpy(me->sess_key, kC_shared, KEY_LEN);
    me->has_sess = 1;
    // print_hex("S derived k", me->sess_key, KEY_LEN);

    printf("計測開始\n");
    int pkt_count = 10000;
    for (int trial = 0; trial < pkt_count; trial++) {
        //pkt_countの桁が変わるごとに表示
        if (trial % 100 == 0) {
            printf("Trial: %d\n", trial);
        }
    
        // printf("\n======= データ転送フェーズ =======\n");
        start_cycles = rte_rdtsc();
        // Sの処理: msgを暗号化して送信パケット作成
        // printf("S -> ");
        unsigned char sid_use[SID_LEN];
        unsigned char kS_pub[PUB_LEN];
        get_raw_pub(nodes[0].dh_sk, kS_pub);
        hash_sid(kS_pub, PUB_LEN, sid_use);
        memcpy(pkt.h.sid, sid_use, SID_LEN);
        pkt.h.status = DATA_TRANS;

        const char *msg = "hello world";
        size_t msg_len = strlen(msg);
        // printf("S sending plaintext: %s\n", msg);

        // --- Padding Fix: 先頭にゼロブロックを付加 ---
        unsigned char zero_pad[PAD_LEN] = {0};

        size_t padded_len = 0;
        unsigned char *padded_msg = concat2(zero_pad, PAD_LEN,(const unsigned char*)msg, msg_len,&padded_len);
        // print_hex("Padded message", padded_msg, padded_len);
        
        aead_encrypt(nodes[0].sess_key, padded_msg, padded_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
        pkt.p.ct_len = padded_len;
        free(padded_msg);

        //センダーのMAC
        // 各リレーの共有鍵 k_i を計算 & m_i を生成
        for (int i = 1; i < NODES - 1; i++) {
            // print_hex("ki", me->k[i], KEY_LEN);
            // HMACでACSEG生成
            unsigned char acseg[ACSEG_LEN];
            unsigned int acseg_len;
            size_t offset = (i - 1) * ACSEG_LEN;
            // print_hex("me->ki", me->ki, KEY_LEN);
            int gmac_result = aes_gmac(me->k[i], KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, pkt.h.acseg_concat + offset, &acseg_len);
            if (gmac_result != 0) {
                fprintf(stderr,"GMAC failed at R%d\n", idx);
                return -1;
            }
        }
        
        pkt.h.idx = 1;
        // ==== DATA_TRANS をパケットに積む ====
        memset(frame, 0, sizeof(frame));
        write_l2l3_min(frame, sizeof(frame));
        wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);
        end_cycles = rte_rdtsc();
        sender_datatrans_cycles += end_cycles - start_cycles;

        // 各リレーの処理: state.next で転送
        int cur = nodes[1].id;
        while (cur != NODES-1) {
            if (router_handle_data_trans(frame, nodes) != 0) die("data_trans fail");
            // printf("R%d -> ", me->id);
            cur++;// = next_addr;
        }
        
        // Rの処理: MAC確認＆復号
        // printf("R(R%d)\n", cur);
        me = &nodes[NODES-1];
        unsigned char padplain[MAX_PTXT];
        start_cycles = rte_rdtsc();
        if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
            fprintf(stderr, "R: parse failed\n");
            return -1;
        }

        // MAC確認
        int t_flag = 0;
        for (int i = 1; i < NODES - 1; i++) {
            unsigned char acseg[ACSEG_LEN];
            unsigned int acseg_len;
            size_t offset = (i - 1) * ACSEG_LEN;
            // ac_plain2 = concat2(pkt.h.acseg_concat, (i - 1) * ACSEG_LEN, pkt.p.ct, pkt.p.ct_len, &ac_plain2_len);
            int gmac_result = aes_gmac(me->k[i], KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, acseg, &acseg_len);
            int flags = 0; // すべて一致なら1
            // acseg_concat内の自身のacsegと比較
            // print_hex("Received ACSEG", pkt.h.acseg_concat + offset, ACSEG_LEN);
            if (memcmp(acseg, pkt.h.acseg_concat + offset, ACSEG_LEN) == 0) {
                // printf("R%d ACSEG match\n", i);
                flags = 1;
            } else {
                printf("R%d ACSEG mismatch\n", i);
            }
            t_flag += flags;
        }
        if (t_flag != ROUTERS) {
            fprintf(stderr, "ACSEG verification failed\n");
        } else {
            // printf("All ACSEGs verified\n");
        }

        // 復号
        if (!aead_decrypt(nodes[NODES-1].sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, padplain))
            die("GCM auth fail at R");

        // --- Padding Fix: 先頭のゼロブロック確認 ---
        int zero_ok = 1;
        for (size_t i = 0; i < PAD_LEN; i++) {
            if (padplain[i] != 0) { zero_ok = 0; break; }
        }
        if (!zero_ok) {
            fprintf(stderr, "Key-commitment verification failed\n");
        }
        // 実際のメッセージ部分抽出
        size_t real_len = padded_len - PAD_LEN;
        unsigned char *real_msg = padplain + PAD_LEN;

        // printf("R(R%d) got plaintext: %.*s\n", cur, (int)real_len, (char *)real_msg);
        end_cycles = rte_rdtsc();
        receiver_datatrans_cycles += end_cycles - start_cycles; 
        // }    

        int blocked = apply_policy_contract((const char *)real_msg);
        
        if (blocked) {
            // printf("\n======= 責任追跡フェーズ =======\n");
            US_CTX *us = US_init("secp256k1");
            if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
            // 通報用ビルド
            wire_len = build_overlay_data_trans(frame, sizeof(frame), &pkt);
            // Rの処理
            // トラフィックを通報
            // 本来は保存したkS_pubとsigを使う
            // 以下の要素をすべて連結 sig_lenとpkt_lenも
            // S_pub,sig,pkt,plain,node[NODES-1].sess_key,com_concat,pi_concat,dh_pk_concat,state_get_prev(me.pkt.h.sid),τ, sigma_s
            size_t r1_len, r2_len, r3_len, r4_len, r5_len, r6_len, r7_len, r8_len, r9_len, r10_len, r11_len, r12_len, r13_len, report_len;
            unsigned char *r1=NULL, *r2=NULL, *r3=NULL, *r4=NULL, *r5=NULL, *r6=NULL, *r7=NULL,*r8=NULL,*r9=NULL,*r10=NULL,*r11=NULL,*r12=NULL,*r13=NULL, *report=NULL;
            
            size_t l2l3_len = write_l2l3_min(frame, sizeof(frame));
            size_t total_len = l2l3_len + wire_len;
            // printf("total_len: %zu\n", total_len);
            
            // //NIZK用のvを生成　　//レシーバのNIZK用のvはいらない
            // uint64_t start_cycles = rte_rdtsc();
            // size_t n2_len, nn2_len;
            // unsigned char *n2 = concat2(pkt.h.com_concat, MAX_COM, pkt.h.pi_concat, ROUTERS * USIG_LEN, &n2_len);
            // unsigned char *nn2 = concat2(pkt.h.dh_pk_concat, ROUTERS * PUB_LEN, n2, n2_len, &nn2_len);
            // // print_hex("nn2", nn2, nn2_len);
            // size_t v2_len; // sufficient size
            // unsigned char *v2 = (unsigned char *)malloc(32 *3 + 33 * 2);
            // //最後のpi_concatを抽出
            // // print_hex("pi_concat", pi_concat, MAX_PI);
            // unsigned char *USpi = pkt.h.pi_concat + ROUTERS * USIG_LEN;
            // // print_hex("USpi", USpi, USIG_LEN);
            // int ver = US_NIZK_Confirm(us, nn2, nn2_len, me->us_x, me->us_y, USpi , USIG_LEN, &v2, &v2_len);
            // if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
            // // print_hex("v2", v2, v2_len);
            // uint64_t end_cycles = rte_rdtsc();
            // report_conf_v_cycles = end_cycles - start_cycles;
            
            
            r1 = concat2(kS_pub, PUB_LEN, (unsigned char *)&sig_size, sizeof(sig_size), &r1_len);// 32 + 4B
            // print_hex("r1", r1, r1_len);
            r2 = concat2(r1, r1_len, (unsigned char *)sig_bytes, sig_size, &r2_len);// +2034B
            // print_hex("r2", r2, r2_len);
            r3 = concat2(r2, r2_len, (unsigned char *)&total_len, sizeof(total_len), &r3_len);// +8B
            // print_hex("r3", r3, r3_len);
            r4 = concat2(r3, r3_len, frame, total_len, &r4_len); // 34 + 267B(アカセグ付き)
            // print_hex("r4", r4, r4_len);
            r5 = concat2(r4, r4_len, real_msg, (int)real_len, &r5_len); // +11B
            r6 = concat2(r5, r5_len, nodes[NODES-1].sess_key, KEY_LEN, &r6_len); // +32B
            r7 = concat2(r6, r6_len, pkt.h.com_concat, MAX_COM, &r7_len);// 132B
            // print_hex("com_concat", pkt.h.com_concat, MAX_COM);
            r8 = concat2(r7, r7_len, pkt.h.pi_concat, MAX_PI, &r8_len);// 132B N2からN5
            r9 = concat2(r8, r8_len, pkt.h.dh_pk_concat, ROUTERS * PUB_LEN, &r9_len);// 128B
            unsigned char prev_state[4];
            memcpy(prev_state, nodes[ROUTERS].addr, sizeof(prev_state));
            r10 = concat2(r9, r9_len, prev_state, sizeof(prev_state), &r10_len);// +4B
            r11 = concat2(r10, r10_len, t, SIG_LEN, &r11_len); // +64B
            // print_hex("τ4", t, SIG_LEN);
            r12 = concat2(r11, r11_len, nodes[NODES-1].state[0].rand_val, sizeof(nodes[NODES-1].state[0].rand_val), &r12_len); // +4B
            // print_hex("r12", r12, r12_len);
            // r13 = concat2(r12, r12_len, v2, v2_len, &r13_len); // + 162B

            unsigned char sigma_r[SIG_LEN];
            size_t sigma_r_len = SIG_LEN;

            sign_data(nodes[NODES-1].sk, r12, r12_len, sigma_r, &sigma_r_len);
            // print_hex("σ_R (signature by receiver)", sigma_r, sigma_r_len);
            report = concat2(r12, r12_len, sigma_r, sigma_r_len, &report_len);
            // printf("Report length: %zu\n", report_len);
            uint64_t total_end_cycles = rte_rdtsc();
            report_cycles += total_end_cycles - start_cycles;
            free(r1); free(r2); free(r3); free(r4); free(r5); free(r6); free(r7); free(r8); free(r9);free(r10); free(r11); free(r12);
        // }
    // }

        // --- 平均クロックサイクル数 ---
        // double avg_tg_sign = tg_sign_cycles / pkt_count;
        // double avg_tg_verify = tg_verify_cycles / pkt_count;
        // double avg_sender_setup = (double)sender_setup_cycles / pkt_count;
        // double avg_receiver_setup = (double)receiver_setup_cycles / pkt_count;
        // double avg_sender_datatrans = (double)sender_datatrans_cycles / pkt_count;
        // double avg_receiver_datatrans = (double)receiver_datatrans_cycles / pkt_count;
        // double avg_repo_v = (double)report_conf_v_cycles / pkt_count;
        // double avg_report = (double)report_cycles / pkt_count;
        // printf("Average TG Sign cycles: %.2f (%.2f µs)\n", avg_tg_sign, avg_tg_sign / (double)tsc_hz * 1e6);
        // printf("Average Sender Setup cycles: %.2f (%.2f µs)\n", avg_sender_setup, avg_sender_setup / (double)tsc_hz * 1e6);
        // printf("Average TG Verify cycles: %.2f (%.2f µs)\n", avg_tg_verify, avg_tg_verify / (double)tsc_hz * 1e6);
        // printf("Average Receiver Setup cycles: %.2f (%.2f µs)\n", avg_receiver_setup, avg_receiver_setup / (double)tsc_hz * 1e6);
        // printf("Average Sender DataTrans cycles: %.2f (%.2f µs)\n", avg_sender_datatrans, avg_sender_datatrans / (double)tsc_hz * 1e6);
        // printf("Average Receiver DataTrans cycles: %.2f (%.2f µs)\n", avg_receiver_datatrans, avg_receiver_datatrans / (double)tsc_hz * 1e6);
        // printf("Average Report v cycles: %.2f (%.2f µs)\n", avg_repo_v, avg_repo_v / (double)tsc_hz * 1e6);
        // printf("Average Report generation cycles: %.2f (%.2f µs)\n", avg_report, avg_report / (double)tsc_hz * 1e6);        

        // --- report を送信 ---
        // === ソケット送信 ===
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(VR_PORT);
        inet_pton(AF_INET, V_ADDR, &serv_addr.sin_addr);

        if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            return 1;
        }
        printf("[Receiver] Connected to Verifier.\n");

        int pkt_count = 1;
        for (;;) {
            if (pkt_count == 2) {
                break;
            }
            printf("[Receiver] Sending report packet #%d\n", pkt_count);
            /* --- 暗号化して送信 --- */
            unsigned char *enc = NULL;
            int enc_len = 0;
            if (tls_encrypt(report, report_len, &enc, &enc_len) != 0) {
                fprintf(stderr, "tls_encrypt failed\n");
                close(sock);
                return 1;
            }
            uint32_t enc_len_n = htonl((uint32_t)enc_len);
            send(sock, &enc_len_n, sizeof(enc_len_n), 0);
            send(sock, enc, enc_len, 0);
            printf("[Receiver] Sent (encrypted) report (%d bytes (ciphertext + tag))\n", enc_len);
            free(enc);
            pkt_count++;
            sleep(0.2);
        }
        close(sock);
    }
            
    // 後処理
    groupsig_signature_free(gsig);
    groupsig_mem_key_free(memkey);
    groupsig_grp_key_free(grpkey);
    groupsig_mgr_key_free(mgrkey);
    groupsig_clear(GROUPSIG_KTY04_CODE);
    return 0;
}