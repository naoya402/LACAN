
#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

#include <time.h>
#include <unistd.h>

// #include "func2.h"
#include "common_func.h"
#include "TLS_func.h"
#include "config.h"

uint64_t pkt_count = 1;
uint64_t Open_cycles = 0;
uint64_t ConfirmVerif_cycles = 0;
uint64_t DisavowVerif_cycles = 0;
uint64_t CommitVerif_cycles = 0;
uint64_t τ_verify_cycles = 0;
uint64_t Reveal_cycles = 0;
uint64_t Trace_cycles = 0;
uint64_t report_cycles = 0;//通報から問い合わせ直前まで
uint64_t inquiry_cycles = 0;//問い合わせから応答受信(検証)まで
// uint64_t identify_cycles = 0;//特定からRevaelまで

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
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    uint64_t tsc_hz = rte_get_tsc_hz();
    // グループ署名初期化
    groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
    // グループ署名に必要な鍵などを読み込み
    groupsig_key_t *grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
    groupsig_key_t *mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);
    groupsig_key_t *memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);
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

    // // Setup (new group)
    groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

    // US context 初期化
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    const EC_POINT *G = EC_GROUP_get0_generator(us->group);
    // ノード初期化
    // Node nodes[NODES];
    Node *nodes = (Node *)rte_malloc(NULL, sizeof(Node) * NODES, 0);
   if (nodes == NULL) {
      printf("Failed to allocate memory for nodes\n");
      return -1;
   }
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    Packet pkt;

    // 検証者Vの処理
    // --- Rと接続 ---
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(VR_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(serv_sock, 1);
    printf("[Verifier] Waiting for report from Receiver...\n");
    int client = accept(serv_sock, NULL, NULL);
    printf("[Verifier] Connected to Receiver.\n");
    
    // // --- ルータと接続 ---
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(VNi_PORT);
    inet_pton(AF_INET, Ni_ADDR, &serv_addr.sin_addr);
    
    // if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //     perror("connect");
    //     return 1;
    // }   
    // リトライ処理
    while (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Verifier: Connect to Router failed. Retrying in 1 sec...");
        sleep(1);
    } 
    printf("[Verifier] Connected to Router.\n");
    
    //検証者の処理ループ
    for (;;) {
        if (pkt_count == 2) {
            break; 
        }
        /* --- 応答 (暗号化) を受信 --- */
        uint32_t resp_len_n;
        if (recv(client, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
            perror("recv len");
            close(client);
            return 1;
        }
        uint32_t resp_len = ntohl(resp_len_n);
        unsigned char *enc_resp = (unsigned char*)malloc(resp_len);
        if (!enc_resp) { close(client); return 1; }

        if (recv(client, enc_resp, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
            perror("recv body");
            free(enc_resp);
            close(client);
            return 1;
        }
        printf("[Verifier] Received (encrypted) report (%d bytes)\n", resp_len);
        // print_hex("Encrypted report", enc_resp, resp_len);

        /* 復号 */
        unsigned char *dec = NULL;
        int dec_len = 0;
        if (tls_decrypt(enc_resp, resp_len, &dec, &dec_len) != 0) {
            fprintf(stderr, "tls_decrypt failed (response)\n");
            free(enc_resp);
            close(client);
            return 1;
        }
        /* dec_len は resp_len の復号後の長さ */
        printf("[Verifier] Decrypted report (%d bytes plaintext)\n", dec_len);
        free(enc_resp);
        
        unsigned char report[dec_len];
        memcpy(report, dec, dec_len);
        free(dec);
        
        // 通報パケットのパース
        uint64_t start_cycles = rte_rdtsc();
        size_t offset = 0;

        // 1) kS_pub 抽出
        unsigned char kS_pub[PUB_LEN];
        memcpy(kS_pub, report + offset, PUB_LEN); offset += PUB_LEN;
        // print_hex("kS_pub", kS_pub, PUB_LEN);

        // 2) グループ署名（Sig）抽出
        size_t sig_len;
        memcpy(&sig_len, report + offset, 4); offset += 4;
        // printf("sig_len: %zu\n", sig_len);
        unsigned char gsig_bytes[sig_len];
        memcpy(gsig_bytes, report + offset, sig_len); offset += sig_len;
        // print_hex("gsig_bytes", gsig_bytes, sig_len);
        groupsig_signature_t *sig = groupsig_signature_import(GROUPSIG_KTY04_CODE, gsig_bytes, sig_len);
        // char *strsig = groupsig_signature_to_string(sig);
        // printf("V: gsig: %s\n", strsig);
        // free(strsig);
        // uint8_t val;
        // char *cstr = groupsig_grp_key_to_string(grpkey);
        // printf("grpkey: %s\n", cstr);
        // free(cstr);
        // print_hex("kS_pub", kS_pub, PUB_LEN);
        // message_t *kSb = message_from_bytes(kS_pub, PUB_LEN);
        // groupsig_verify(&val, sig, kSb, grpkey);
        // printf("TGsig verification: %s\n", val ? "valid" : "invalid");

        // 3) Packet構造体の復元
        size_t pkt_len;
        memcpy(&pkt_len, report + offset, 8);//sizeof(pkt_len));
        offset += 8;//sizeof(pkt_len);
        // printf("pkt_len: %lu\n", pkt_len);
        // Packet pkt;
        unsigned char frame[pkt_len];
        memcpy(frame, report + offset, pkt_len); offset += pkt_len;
        // print_hex("frame", frame, pkt_len);
        if (parse_frame_to_pkt(frame, sizeof(frame), &pkt) != 0) {
                    fprintf(stderr, "parse failed\n");
                    return -1;
        }
        // print_hex("ACSEG: ", pkt.h.acseg_concat, ACSEG_LEN * ROUTERS);

        // 4) 平文（plain）抽出
        size_t plain_len = pkt.p.ct_len - PAD_LEN;
        unsigned char plain_recv[plain_len];// パディング付きの平文
        memcpy(plain_recv, report + offset, pkt.p.ct_len); offset += plain_len;
        // printf("plain_recv: %.*s\n", (int)plain_len, plain_recv);

        // 5) セッション鍵
        unsigned char sess_key[KEY_LEN];
        memcpy(sess_key, report + offset, KEY_LEN); offset += KEY_LEN;
        // print_hex("sess_key", sess_key, KEY_LEN);

        // 6) concat
        unsigned char com_concat[MAX_COM];
        unsigned char pi_concat[MAX_PI];
        unsigned char dh_pk_concat[ROUTERS * PUB_LEN];
        memcpy(com_concat, report + offset, MAX_COM); offset += MAX_COM;
        // print_hex("com_concat", com_concat, MAX_COM);
        memcpy(pi_concat, report + offset, MAX_PI); offset += MAX_PI;
        // print_hex("pi_concat", pi_concat, MAX_PI);
        memcpy(dh_pk_concat, report + offset, ROUTERS * PUB_LEN); offset += ROUTERS * PUB_LEN;
        // print_hex("dh_pk_concat", dh_pk_concat, ROUTERS * PUB_LEN);

        // 7) prev_state
        unsigned char prev_state[4];
        memcpy(&prev_state, report + offset, 4); offset += 4;
        // printf("prev_state: %d\n", prev_state);

        // 8) τ
        unsigned char tau[SIG_LEN];
        memcpy(tau, report + offset, SIG_LEN); offset += SIG_LEN;
        // print_hex("tau", tau, SIG_LEN);

        // 9) rand_val
        unsigned char rand_val[4];
        memcpy(rand_val, report + offset, sizeof(rand_val)); offset += sizeof(rand_val);
        // print_hex("rand_val", rand_val, sizeof(rand_val));

        // 10) σ_R (Receiver署名)
        unsigned char sigma_r[SIG_LEN];
        memcpy(sigma_r, report + offset, SIG_LEN); offset += SIG_LEN;
        // size_t sigma_r_len = SIG_LEN;
        // print_hex("sigma_r", sigma_r, SIG_LEN);

        // printf("Parsed report packet successfully (total %zu bytes parsed)\n", offset);

        // 通報の正当性検証
        // 1) sigma 検証
        // --- 署名対象データ (σ_r を除く部分) ---
        size_t r_len = dec_len - SIG_LEN;  // report 全体から σ_r を除いた長さ
        unsigned char *r = (unsigned char *)malloc(r_len);
        memcpy(r, report, r_len);
        // print_hex("r (data signed by Receiver)", r, r_len);
        // --- 署名検証 ---
        if (verify_sig(nodes[NODES-1].pk, r, r_len, sigma_r, SIG_LEN)) {
            // printf("σ_r verification succeeded\n");
        } else {
            printf("σ_r verification failed\n");
        }

        // 2) SID 再計算: 例 -> SID = SHA256( S_pub ) or whatever your scheme uses
        unsigned char sid_chk[SID_LEN];
        // --- 署名をバイナリにエクスポート ---
        byte_t *sig_bytes = NULL;
        uint32_t sig_size = 0;
        groupsig_signature_export(&sig_bytes, &sig_size, sig);
        // printf("Exported signature length: %u bytes\n", sig_size);
      
        // SID 生成
        hash_sid(kS_pub, PUB_LEN, sid_chk);
        // print_hex("SID(S)=H(kC)", pkt.h.sid, SID_LEN);
        if (memcmp(sid_chk, pkt.h.sid, SID_LEN) != 0) { /* mismatch */ }
        // printf("SID check: match\n");

        // 3) groupsig 検証
        // char *strsig = groupsig_signature_to_string(sig);
        // printf("V: gsig: %s\n", strsig);
        // free(strsig);
        uint8_t val;
        // print_hex("kS_pub", kS_pub, PUB_LEN);
        // message_t *kSb = message_from_bytes(kS_pub, PUB_LEN);
        size_t tsconcat_len;
        unsigned char *tsconcat = concat2(pkt.p.peer_pub, PUB_LEN, pkt.p.ts, 4, &tsconcat_len);
        message_t *ppp = message_from_bytes(tsconcat, tsconcat_len);
        groupsig_verify(&val, sig, ppp, grpkey);
        // printf("TGsig verification: %s\n", val ? "valid" : "invalid");

        // 4) ペイロード復号
        // ここでは pkt.p.iv, pkt.p.ct, pkt.p.tag を利用する
        unsigned char padplain[MAX_PTXT];
        if (!aead_decrypt(sess_key, pkt.p.ct, pkt.p.ct_len, pkt.h.sid, pkt.p.iv, pkt.p.tag, padplain)) {
            /* decrypt fail */
        }
        // --- Padding Fix: 先頭のゼロブロック確認 ---
        int zero_ok = 1;
        size_t padded_len = 0;
        
        for (size_t i = 0; i < PAD_LEN; i++) {
            if (padplain[i] != 0) { zero_ok = 0; break; }
        }
        if (!zero_ok) {
            fprintf(stderr, "Key-commitment verification failed\n");
        }
        // 実際のメッセージ部分抽出
        // size_t real_len = padded_len - PAD_LEN;
        unsigned char *real_msg = padplain + PAD_LEN;
        // printf("plain_out: %.*s\n", (int)pkt.p.ct_len, plain_out);
        if (memcmp(real_msg, plain_recv, plain_len) != 0) { /* mismatch */ }
        // printf("Decrypt result match: %.*s\n", (int)plain_len, real_msg);
        
        // 5) コントラクト検証
        int blocked = apply_policy_contract((const char *)plain_recv);
        if (!blocked) {// 以降の処理は行わない
        } 
        // printf("Policy contract False.\n");

        // 6) 前ホップ検証
        int rec_id = pkt.h.idx; //5(ROUTERS + 1)
        int prev_idx = prev_state[3]; //今回はアドレス1桁目がidx
        
        // // printf("Verify π%d success \n", rec_id);
        // τi-1検証
        unsigned char *m = NULL, *mm = NULL; size_t m_len = 0, mm_len = 0;
        m = concat2(pkt.h.sid, SID_LEN, nodes[rec_id].addr, sizeof(nodes[rec_id].addr), &m_len);
        mm = concat2(m, m_len, prev_state, sizeof(prev_state), &mm_len);
        // print_hex("m for τi-1", m, m_len);
        if (!verify_sig(nodes[prev_idx].pk, mm, mm_len, tau, SIG_LEN)) {
            fprintf(stderr, "Verify τ%d failed\n", prev_idx);
            free(m);
            free(mm);
            return -1;
        }
        free(m);
        // printf("Verify τ%d success\n", prev_idx);
        uint64_t end_cycles = rte_rdtsc();
        report_cycles += end_cycles - start_cycles;

        // // === Open（署名者を特定） ===
        start_cycles = rte_rdtsc();
        uint64_t id = UINT64_MAX;
        int rc = groupsig_open(&id, NULL, NULL, sig, grpkey, mgrkey, gml);
        if (rc == IOK) {
            // printf("Open success: member ID = %lu\n", id);
        } else {
            printf("Open failed.\n");
        }
        end_cycles = rte_rdtsc();
        Open_cycles += end_cycles - start_cycles;
        
        // ルータから得たidリストと比較してSを特定
        // uint64_t id = 0;
        const char *signer = router_addresses[id]; // 仮にidをインデックスとしてSを特定
        // gml_entry_t *entry = gml_get(gml, id);
        // if (!entry) {
        //     fprintf(stderr, "No entry found for ID %lu\n", id);
        // }
        // char *entry_str = gml_entry_to_string(entry);
        // printf("=== GML Entry ID %lu ===\n%s\n", id, entry_str);
        // free(entry_str);

        // 各ノードに問い合わせてS特定
        // idがそのままSのIDとする 本来はidリストと比較してSを特定
        uint64_t s_id = id;

        // 送信パケットの構築
        // ペイロード部の連結
        size_t pay_len = IV_LEN + 2 + pkt.p.ct_len + TAG_LEN;
        unsigned char *pay_buf1; size_t pay_buf1_len;
        unsigned char *pay_buf2; size_t pay_buf2_len;
        unsigned char *pay_buf3; size_t pay_buf3_len;
        uint16_t ctlen_n = htons((uint16_t)pkt.p.ct_len);
        pay_buf1 = concat2((unsigned char*)&ctlen_n, 2, pkt.p.ct, pkt.p.ct_len, &pay_buf1_len);
        // pay_buf1 = concat2(pkt.p.iv, IV_LEN, (unsigned char*)&ctlen_n, 2, &pay_buf1_len);
        // pay_buf2 = concat2(pay_buf1, pay_buf1_len, pkt.p.ct, pkt.p.ct_len, &pay_buf2_len);
        // pay_buf3 = concat2(pay_buf2, pay_buf2_len, pkt.p.tag, TAG_LEN, &pay_buf3_len);
        unsigned char *ac_plain1; size_t ac_plain1_len;
        unsigned char *ac_plain2; size_t ac_plain2_len;
        unsigned char *ac_plain3; size_t ac_plain3_len;
        unsigned char *ac_plain4; size_t ac_plain4_len;
        unsigned char *ac_plain5; size_t ac_plain5_len;
        unsigned char *inq; size_t inq_len;
        
        //公開鍵の準備
        EC_POINT *Y = nodes->us_y;
        ac_plain1 = concat2(pkt.h.sid, SID_LEN, pay_buf1, pay_buf1_len, &ac_plain1_len);
        // print_hex("AC_SEG: ", pkt.h.acseg_concat, (pkt.h.idx - 1) * ACSEG_LEN);
        // print_hex("ac_plain1", ac_plain1, ac_plain1_len);
        // // Sになるまで問い合わせループ
        uint32_t cur_id = prev_idx; // 返された前ノードから開始
        int flags = 0;
        while (1) {// ルータに問い合わせてSを特定
            ac_plain2 = concat2(ac_plain1, ac_plain1_len, dh_pk_concat, cur_id * PUB_LEN, &ac_plain2_len);
            // print_hex("ac_plain2", ac_plain2, ac_plain2_len);
            // print_hex("AC_SEG: ", pkt.h.acseg_concat, (ROUTERS) * ACSEG_LEN);
            ac_plain3 = concat2(ac_plain2, ac_plain2_len, com_concat, cur_id * COM_LEN, &ac_plain3_len);
            // print_hex("ac_plain3", ac_plain3, ac_plain3_len);
            // if (cur_id > 0) {
            ac_plain4 = concat2(ac_plain3, ac_plain3_len, pi_concat, cur_id * USIG_LEN, &ac_plain4_len);
            // print_hex("ac_plain4", ac_plain4, ac_plain4_len);
            ac_plain5 = concat2(ac_plain4, ac_plain4_len, pi_concat + cur_id * USIG_LEN, USIG_LEN, &ac_plain5_len);
            inq = ac_plain5;//concat2(ac_plain3, ac_plain3_len, W_bytes, W_len, &inq_len);
            inq_len = ac_plain5_len;
            // // === ソケット送信 ===
            // sockaddr_in serv_addr{};
            // serv_addr.sin_family = AF_INET;
            // serv_addr.sin_port = htons(9010);
            // inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);
            
            // if (connect(sock, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            //     perror("connect");
            //     return 1;
            // }

            // uint32_t inq_len_n = htonl(inq_len);
            // send(sock, &inq_len_n, sizeof(inq_len_n), 0);
            // send(sock, inq, inq_len, 0);
            // printf("[Verifier] Sent INQ to R%d\n", 1);//cur_id);

            /* --- 暗号化して送信 --- */
            unsigned char *enc = NULL;
            int enc_len = 0;
            if (tls_encrypt(inq, inq_len, &enc, &enc_len) != 0) {
                fprintf(stderr, "tls_encrypt failed\n");
                close(sock);
                return 1;
            }
            uint32_t enc_len_n = htonl((uint32_t)enc_len);
            send(sock, &enc_len_n, sizeof(enc_len_n), 0);
            send(sock, enc, enc_len, 0);
            printf("[Verifier] Sent (encrypted) inq request (%d bytes ciphertext + tag)\n", enc_len);
            // print_hex("enc inq", enc, enc_len);
            free(enc);
            
            
            //問い合わせの応答受信
            // uint32_t reinq_len_n;
            // recv(sock, &reinq_len_n, sizeof(reinq_len_n), 0);
            // uint32_t reinq_len = ntohl(reinq_len_n);
            
            // unsigned char reinq[reinq_len];
            // recv(sock, reinq, reinq_len, MSG_WAITALL);
            // printf("[Verifier] Received REINQ (%u bytes) from R%d\n", reinq_len, 1);//cur_id);
            // print_hex("reinq", reinq, reinq_len);

            // /* --- 応答 (暗号化) を受信 --- */
            uint32_t resp_len_n;
            if (recv(sock, &resp_len_n, sizeof(resp_len_n), 0) != sizeof(resp_len_n)) {
                perror("recv len");
                close(sock);
                return 1;
            }
            uint32_t resp_len = ntohl(resp_len_n);
            // printf("resp_len: %u\n", resp_len);
            unsigned char *enc_resp = (unsigned char*)malloc(resp_len);
            if (!enc_resp) { close(sock); return 1; }

            if (recv(sock, enc_resp, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
                perror("recv body");
                free(enc_resp);
                close(sock);
                return 1;
            }
            printf("[Verifier] Received (encrypted) reinq (%d bytes)\n", resp_len);

            /* 復号 */
            unsigned char *dec = NULL;
            int dec_len = 0;
            if (tls_decrypt(enc_resp, resp_len, &dec, &dec_len) != 0) {
                fprintf(stderr, "tls_decrypt failed (response)\n");
                free(enc_resp);
                close(sock);
                return 1;
            }
            /* dec_len は resp_len の復号後の長さ */
            printf("[Verifier] Decrypted reinq (%d bytes plaintext)\n", dec_len);
            free(enc_resp);
            unsigned char reinq[dec_len];
            memcpy(reinq, dec, dec_len);
            // print_hex("reinq", reinq, dec_len);
            free(dec);
            
            // ノードからの応答パケットのパース
            uint64_t inqstart_cycles = rte_rdtsc();//前ホップが返ってきてから送信するまで
            size_t offset = 0;
            unsigned char tmp_addr[4]; // 前ノードアドレス
            // size_t R_len = 33;
            size_t v_len = 32 *3 + 33 * 2;
            unsigned char v[v_len];
            size_t vp_len = 32 *2 + 33 * 3;
            unsigned char vp[vp_len];
            // unsigned char R_bytes[R_len];
            unsigned char tau[SIG_LEN];
            // unsigned char rand_val[4];
            int flag = 0; // 各ノードの検証結果フラグ
            memcpy(v , reinq + offset, v_len); offset += v_len;
            // print_hex("Received v: ", v, v_len);
            memcpy(vp, reinq + offset, vp_len); offset += vp_len;
            // print_hex("Received vp: ", vp, vp_len);
            memcpy(tau, reinq + offset, SIG_LEN); offset += SIG_LEN;
            // print_hex("Received tau: ", tau, SIG_LEN);
            memcpy(rand_val, reinq + offset, sizeof(rand_val)); offset += sizeof(rand_val);
            // print_hex("Received rand_val: ", rand_val, sizeof(rand_val));
            memcpy(tmp_addr, reinq + offset, sizeof(tmp_addr)); offset += sizeof(tmp_addr);
            // printf("Received tmp_addr: %d.%d.%d.%d\n", tmp_addr[0], tmp_addr[1], tmp_addr[2], tmp_addr[3]);
            memcpy(&flag, reinq + offset, 2); offset += 2;
            //idxを取得
            int tmp_idx = tmp_addr[3]; // 今回はアドレス1桁目がidx
            
            // π_i-1を検証
            //pi_concatから前ノード分を取り出す
            unsigned char *pi = (unsigned char *)malloc(USIG_LEN);
            memcpy(pi, pi_concat + cur_id * USIG_LEN, USIG_LEN);
            // print_hex("pi", pi, USIG_LEN);
            size_t pi_len = USIG_LEN;
            //com_concatと取り出した残りのΠからnを生成
            size_t n_len, nn_len;
            unsigned char *n = NULL;
            unsigned char *nn = NULL;
            n = concat2(com_concat, cur_id * COM_LEN, pi_concat, cur_id * USIG_LEN, &n_len);
            nn = concat2(dh_pk_concat, cur_id * PUB_LEN, n, n_len, &nn_len);
            // print_hex("nn", nn, nn_len);
            // print_hex("π", pi, pi_len);
            
            v_len = vp_len = 32 *3 + 33 * 2;
            start_cycles = rte_rdtsc();
            int ver = US_NIZK_VerifyC(us, nodes[tmp_idx].us_y, nodes[tmp_idx + 1].us_y, nn, nn_len, pi, pi_len, v, v_len);
            uint64_t mid_cycles = rte_rdtsc();
            ConfirmVerif_cycles += mid_cycles - start_cycles;
            int ver2 = US_NIZK_VerifyD(us, nodes[tmp_idx].us_y, nodes[tmp_idx + 1].us_y, nn, nn_len, pi, pi_len, vp, vp_len);
            end_cycles = rte_rdtsc();
            DisavowVerif_cycles += end_cycles - mid_cycles;
            // printf("Verify π%d results: ver=%d, ver2=%d\n", cur_id, ver, ver2);
            if (ver == 1 && ver2 ==0) {
                // printf("NIZK Signature CONFIRMED.\n");
                // printf("Verify π%d success\n", cur_id);
            } else if (ver == 0 && ver2 ==1) {
                // printf("NIZK Signature NOT confirmed.\n");
                fprintf(stderr, "Verify π%d failed\n", cur_id);
                return -1;
            } else {
                fprintf(stderr, "Verify π%d inconsistent result\n", cur_id);
                return -1;
            }
            free(pi);
            free(n);
            // free(v);

            //最後のcom_concatを抽出
            start_cycles = rte_rdtsc();
            unsigned char com_chk[COM_LEN];//コミット確認用
            unsigned char *com = com_concat + (cur_id - 1) * COM_LEN;
            // ver = EC_Com_Verify(us, tau, SIG_LEN, rand_val, sizeof(rand_val), G, com, USIG_LEN);
            Commit256(tau, SIG_LEN, rand_val, sizeof(rand_val), com_chk);
            // print_hex("com", com, COM_LEN);
            // print_hex("com_chk", com_chk, COM_LEN);
            if (memcmp(com_chk, com, COM_LEN) == 0) {
                // printf("Commitment VERIFIED.\n");
            } else if (ver == 0) {
                printf("Commitment NOT verified.\n");
                return -1;
            }
            end_cycles = rte_rdtsc();
            CommitVerif_cycles += end_cycles - start_cycles;

            // τi-1検証
            unsigned char *m = NULL, *mm = NULL; size_t m_len = 0, mm_len = 0;
            start_cycles = rte_rdtsc();
            m = concat2(pkt.h.sid, SID_LEN, nodes[tmp_idx + 1].addr, sizeof(nodes[tmp_idx + 1].addr), &m_len);
            mm = concat2(m, m_len, nodes[tmp_idx + 2].addr, sizeof(nodes[tmp_idx + 2].addr), &mm_len);
            // print_hex("m for τi-1", mm, mm_len);
            if (!verify_sig(nodes[tmp_idx].pk, mm, mm_len, tau, SIG_LEN)) {
                fprintf(stderr, "Verify τ%d failed\n", tmp_idx);
                free(m);
                free(mm);
                return -1;
            }
            free(m);
            free(mm);
            end_cycles = rte_rdtsc();
            τ_verify_cycles += end_cycles - start_cycles;

            inquiry_cycles += end_cycles - inqstart_cycles;
            
            if (s_id != tmp_idx) {
                // 次のルータへの問い合わせ準備
                // next_addr_n = htonl((uint32_t)cur_id);
                cur_id = ntohl(tmp_idx);
                flags += flag;
                break; // テスト用に1回で抜ける
                printf("[Verifier] Continuing to next Router...\n");
            } else {
                printf("Router R%d is identified as the Sender\n", tmp_idx);
                flags += flag;
                break;
            }
            close(sock);
            close(client);
            // sleep(3); // 少し待つ
        }

        // // flagsからセッションとペイロードのリンクの合意をとる
        // すべてオネストな検証をしていれば経由した1~nのリレーになっているはず
        // 攻撃者が1人ならn-1、攻撃者が2人ならn-2、...となるはず
        // printf("Flags value: %d\n", flags);
        // // === Reveal（特定メンバーを公開処理(CRLに入れる)） ===
        start_cycles = rte_rdtsc();
        trapdoor_t *trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE);
        rc = groupsig_reveal(trapdoor, crl, gml, id);
        if (rc == IOK && trapdoor != NULL) {
            // printf("Reveal success: trapdoor valid, member ID = %lu added to CRL.\n", id);
        } else {
            printf("Reveal failed.\n");
        }
        end_cycles = rte_rdtsc();
        Reveal_cycles += end_cycles - start_cycles;

        // // CRLをRに送信?(共有している想定なら不要)
        // // Rの処理
        // === Trace（署名が公開済み(CRL登録済)メンバーによるものか確認） ===
        start_cycles = rte_rdtsc();
        uint8_t traced = 0;
        rc = groupsig_trace(&traced, sig, grpkey, crl, NULL, NULL);
        if (rc == IOK) {
            printf("Trace result: %d (1 = traced, 0 = not traced)\n", (int)traced);
        } else {
            printf("Trace failed.\n");
        }
        end_cycles = rte_rdtsc();
        Trace_cycles += end_cycles - start_cycles;
        pkt_count++;
    }
    // 平均サイクル数表示
    double avg_report = (double)report_cycles / (double)pkt_count;
    double avg_Open = (double)Open_cycles / (double)pkt_count;
    double avg_US_confirm = (double)ConfirmVerif_cycles / (double)pkt_count;
    double avg_US_disavow = (double)DisavowVerif_cycles / (double)pkt_count;
    double avg_CommitVerif = (double)CommitVerif_cycles / (double)pkt_count;
    double avg_τ_verify = (double)τ_verify_cycles / (double)pkt_count;
    double avg_Reveal = (double)Reveal_cycles / (double)pkt_count;
    double avg_Trace = (double)Trace_cycles / (double)pkt_count;
    double avg_inquiry = (double)inquiry_cycles / (double)pkt_count;
    printf("Average Report processing cycles: %.2f (%.2f µs)\n", avg_report, avg_report / (double)tsc_hz * 1e6);
    printf("Average Open cycles: %.2f (%.2f µs)\n", avg_Open, avg_Open / (double)tsc_hz * 1e6);
    printf("Average US_NIZK_Confirm cycles: %.2f (%.2f µs)\n", avg_US_confirm, avg_US_confirm / (double)tsc_hz * 1e6);
    printf("Average US_NIZK_Disavow cycles: %.2f (%.2f µs)\n", avg_US_disavow, avg_US_disavow / (double)tsc_hz * 1e6);
    printf("Average Com_Verify cycles: %.2f (%.2f µs)\n", avg_CommitVerif, avg_CommitVerif / (double)tsc_hz * 1e6);
    printf("Average τ_verify cycles: %.2f (%.2f µs)\n", avg_τ_verify, avg_τ_verify / (double)tsc_hz * 1e6);
    printf("Average Reveal cycles: %.2f (%.2f µs)\n", avg_Reveal, avg_Reveal / (double)tsc_hz * 1e6);
    printf("Average Trace cycles: %.2f (%.2f µs)\n", avg_Trace, avg_Trace / (double)tsc_hz * 1e6);
    printf("Average Inquiry processing cycles: %.2f (%.2f µs)\n", avg_inquiry, avg_inquiry / (double)tsc_hz * 1e6);
    close(sock);
    close(serv_sock);
    close(client);
    return 0;
}