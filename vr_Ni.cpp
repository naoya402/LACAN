#include "common_func.h"
#include "TLS_func.h"
#include "config.h"

uint64_t pkt_count = 1;
uint64_t Confirm_cycles = 0;
uint64_t Disavow_cycles = 0;
uint64_t router_cycles = 0;


int main(int argc, char *argv[]) {
    // int ret = rte_eal_init(argc, argv);
    // if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    uint64_t tsc_hz = 2000000000;//rte_get_tsc_hz();
    // signal(SIGPIPE, SIG_IGN);
    // US context 初期化
    US_CTX *us = US_init("secp256k1");
    if (!us) { fprintf(stderr,"US_init error\n"); return 1; }
    // ノード初期化
    // Node *nodes = (Node *)rte_malloc(NULL, sizeof(Node) * NODES, 0);
    Node nodes[NODES];
    // node_init(&nodes[0], 0);//, "S(R0)");
    for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    // 今回はR_ROUTERSが受け取った仮定
    Node *me = &nodes[ROUTERS];


    // stateの生成
    // --- SID 生成 ---
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(nodes[0].dh_sk, kS_pub);
    unsigned char sid[SID_LEN];
    hash_sid(kS_pub, PUB_LEN, sid);
    int prev_idx = 1; //me->state[0].prev_addr; //今回は1を返す
    unsigned char prev_addr[4];
    memcpy(prev_addr, nodes[prev_idx].addr, sizeof(prev_addr)); 
    // print_hex("prev_addr", prev_addr, 4);
    // // 受信側で τ_{prev_addr} を生成(検証用)
    Node *no = &nodes[prev_idx];
    unsigned char t[SIG_LEN];
    size_t t_len = SIG_LEN, g_len, g2_len;
    unsigned char sta_addr[4], sta_next_addr[4];
    memcpy(sta_addr, nodes[prev_idx + 1].addr, sizeof(sta_addr));
    memcpy(sta_next_addr, nodes[prev_idx + 2].addr, sizeof(sta_next_addr));
    // τ_ROUTERS用のデータ
    unsigned char *g = concat2(sid, SID_LEN, sta_addr, 4, &g_len);
    unsigned char *g2 = concat2(g, g_len, sta_next_addr, 4, &g2_len);
    // print_hex("g for τ_prev_addr", g2, g2_len);
    sign_data(no->sk, g2, g2_len, t, &t_len);
    free(g);
    free(g2);
    // print_hex("τi generated at R1", t, tau_len);
    // unsigned char *tau = me->state[0].tau;
    // ステートの保存
    unsigned char temp_rand[4] = {0x11, 0x11, 0x11, 0x11};
   state_set(me, sid, prev_addr, nodes[ROUTERS + 1].addr, no->addr, t, temp_rand);

    // --- 通報パケット受信 ---
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(VNi_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    // bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr));
    if (bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed"); 
        return 1;
    }
    listen(serv_sock, 1);
    printf("[Node] Waiting for report from Receiver...\n");
    
    int client = accept(serv_sock, NULL, NULL);
    printf("[Node] Connected to Verifier.\n");
    // uint32_t len_n;
    // recv(client, &len_n, sizeof(len_n), 0);
    // uint32_t len = ntohl(len_n);
    
    // unsigned char inq[len];
    // recv(client, inq, len, MSG_WAITALL);
    //リレーの処理ループ
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
        unsigned char *enc_inq = (unsigned char*)malloc(resp_len);
        if (!enc_inq) { close(client); return 1; }
        
        if (recv(client, enc_inq, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
            perror("recv body");
            free(enc_inq);
            close(client);
            return 1;
        }
        printf("[Node] Received (encrypted) inq (%d bytes)\n", resp_len);
        // print_hex("Encrypted inq", enc_inq, resp_len);
        
        /* 復号 */
        unsigned char *dec = NULL;
        int dec_len = 0;
        if (tls_decrypt(enc_inq, resp_len, &dec, &dec_len) != 0) {
            fprintf(stderr, "tls_decrypt failed (response)\n");
            free(enc_inq);
            close(client);
            return 1;
        }
        free(enc_inq);
        /* dec_len は resp_len の復号後の長さ */
        printf("[Node] Decrypted inq (%d bytes plaintext)\n", dec_len);
        
        // print_hex("Decrypted inq", dec, dec_len);
        unsigned char inq[dec_len];
        memcpy(inq, dec, dec_len);
        free(dec);
        
        // printf("[Node] Received inq (%u bytes)\n", dec_len);
        // print_hex("inq", inq, dec_len);
        
        uint64_t router_start_cycles = rte_rdtsc();
        // 問い合わせパケットのパース
        uint64_t start_cycles = rte_rdtsc();
        // inq: SID(16B) || Payload(11+PADD_LEN B) || dh_pk_concat || com_concat || pi_concat || pi 
        size_t inq_offset = 0;
        // 1) SID
        unsigned char sid[SID_LEN];
        memcpy(sid, inq + inq_offset, SID_LEN); inq_offset += SID_LEN;
        // print_hex("SID", sid, SID_LEN);

        // 2) 平文 ct_len (2B)
        uint16_t ct_len_n;
        memcpy(&ct_len_n, inq + inq_offset, 2); inq_offset += 2;

        uint16_t ct_len = ntohs(ct_len_n);
        // printf("ct_len = %u\n", ct_len);

        // 3) CT（暗号文）
        unsigned char ct[ct_len];
        memcpy(ct, inq + inq_offset, ct_len); inq_offset += ct_len;
        // print_hex("CT", ct, ct_len);

        // 4) dh_pk_concat: cur_id * PUB_LEN
        int cur_id = me->id;  // リレー自身のIDを使う
        size_t dh_concat_len = cur_id * PUB_LEN;
        unsigned char dh_pk_concat[dh_concat_len];
        memcpy(dh_pk_concat, inq + inq_offset, dh_concat_len); inq_offset += dh_concat_len;
        // print_hex("dh_pk_concat", dh_pk_concat, dh_concat_len);

        // 5) com_concat: cur_id * COM_LEN
        size_t com_concat_len = cur_id * COM_LEN;
        unsigned char com_concat[com_concat_len];
        if (com_concat_len > 0) {
            memcpy(com_concat, inq + inq_offset, com_concat_len);
            // print_hex("com_concat", com_concat, com_concat_len);
        }
        inq_offset += com_concat_len;

        // 6) pi_concat_trim: cur_id * USIG_LEN
        size_t pi_trim_len =  cur_id * USIG_LEN;
        unsigned char pi_concat_trim[pi_trim_len];
        if (pi_trim_len > 0) {
            memcpy(pi_concat_trim, inq + inq_offset, pi_trim_len);
            // print_hex("pi_concat_trim", pi_concat_trim, pi_trim_len);
        }
        inq_offset += pi_trim_len;

        // 7) 最後の PI（1つ）= USIG_LEN
        unsigned char pi[USIG_LEN];
        memcpy(pi, inq + inq_offset, USIG_LEN); inq_offset += USIG_LEN;
        uint64_t end_cycles = rte_rdtsc();

        // 問い合わせ返答の生成
        // 1) 前ノードのアドレスを取得
        unsigned char prev[4], tau[SIG_LEN];
        // memcpy(prev, prev_addr, 4); 
        memcpy(prev, state_get_prev(me, sid), 4);
        memcpy(tau, state_get_tau(me, sid), SIG_LEN);
        // 2) 検証するvを生成
        start_cycles = rte_rdtsc();
        unsigned char *n = NULL, *nn = NULL;
        size_t n_len, nn_len;
        n = concat2(com_concat, cur_id * COM_LEN, pi_concat_trim, cur_id * USIG_LEN, &n_len);
        nn = concat2(dh_pk_concat, cur_id * PUB_LEN, n, n_len, &nn_len);
        // print_hex("nn", nn, nn_len);
        
        size_t v_len; // sufficient size
        unsigned char *v = (unsigned char *)malloc(32 *3 + 33 * 2);
        int ver = US_NIZK_Confirm(us, nn, nn_len, me->us_x, nodes[prev_idx + 1].us_y, pi, USIG_LEN, &v, &v_len);
        if (!ver) { fprintf(stderr,"US_NIZK_Confirm error\n"); return 1; }
        // print_hex("v", v, v_len);

        uint64_t mid_cycles = rte_rdtsc();
        // printf("US_NIZK_Confirm took %lu cycles\n", mid_cycles - start_cycles);
        Confirm_cycles += (mid_cycles - start_cycles);

        size_t vp_len;
        unsigned char *vp;
        ver = US_NIZK_Disavow(us, nn, nn_len, me->us_x, nodes[prev_idx + 1].us_y, pi, USIG_LEN, &vp, &vp_len);
        if (!ver) { fprintf(stderr,"US_NIZK_Disavow error\n"); return 1; }
        end_cycles = rte_rdtsc();
        // printf("US_NIZK_Disavow took %lu cycles\n", end_cycles - mid_cycles);
        Disavow_cycles += (end_cycles - mid_cycles);

        // 3) flagsを取得
        int flags = 0; // すべて一致なら1
        // ステート内の自身のhashと比較
        unsigned char ct_hash[SHA256_DIGEST_LENGTH];
        SHA256(ct, ct_len, ct_hash);
        if (memcmp(ct_hash,  ct_hash, SHA256_DIGEST_LENGTH) == 0) {
            printf("R%d hash match\n", me->id);
            flags = 1;
        } else {
            printf("R%d hash mismatch\n", me->id);
        }


        // 5) 検証者に返す
        // v(162B) || vp(162B) || τ(SIG_LEN) || rand(4B) || prev_addr(4B) || flags(2B) 
        // size_t reinq_len = 4 + SIG_LEN + 2;
        unsigned char *reinq1; size_t reinq1_len;
        unsigned char *reinq2; size_t reinq2_len;
        unsigned char *reinq3; size_t reinq3_len;
        unsigned char *reinq4; size_t reinq4_len;
        unsigned char *reinq; size_t reinq_len;
        
        reinq1 = concat2(v, v_len, vp, vp_len, &reinq1_len);
        // print_hex("v", v, v_len);
        // print_hex("vp", vp, vp_len);
        reinq2 = concat2(reinq1, reinq1_len, tau, SIG_LEN, &reinq2_len);
        // print_hex("τ3", t, SIG_LEN);
        reinq3 = concat2(reinq2, reinq2_len, me->state[0].rand_val, sizeof(me->state[0].rand_val), &reinq3_len);
        reinq4 = concat2(reinq3, reinq3_len, prev, 4, &reinq4_len);
        // printf("prev_addr: %d.%d.%d.%d\n", prev[0], prev[1], prev[2], prev[3]);
        reinq = concat2(reinq4, reinq4_len, (unsigned char*)&flags, 2, &reinq_len);
        // print_hex("reinq", reinq, reinq_len);
        
        // print_hex("[Node] Sending reinq to Verifier: ", reinq, reinq_len);
        // uint32_t reinq_len_n = htonl(reinq_len);
        // send(client, &reinq_len_n, sizeof(reinq_len_n), 0);
        // send(client, reinq, reinq_len, 0);
        /* --- 暗号化して送信 --- */
        unsigned char *enc = NULL;
        int enc_len = 0;
        if (tls_encrypt(reinq, reinq_len, &enc, &enc_len) != 0) {
            fprintf(stderr, "tls_encrypt failed\n");
            close(client);
            return 1;
        }
        // printf("[Node] Encrypted reinq (%d bytes ciphertext + tag)\n", enc_len);
        uint32_t enc_len_n = htonl((uint32_t)enc_len);
        send(client, &enc_len_n, sizeof(enc_len_n), 0);
        send(client, enc, enc_len, 0);
        printf("[Node] Sent (encrypted) reinq request (%d bytes (ciphertext+ tag))\n", enc_len);
        end_cycles = rte_rdtsc();
        router_cycles += (end_cycles - router_start_cycles);
        // printf("Processed packets: %lu\n", pkt_count);
        pkt_count++;
        free(n); free(nn); free(v); free(vp); free(reinq); free(enc);
    }
    // 平均サイクル数表示
    double avg_time_confirm = (double)Confirm_cycles / (double)pkt_count;
    double avg_time_disavow = (double)Disavow_cycles / (double)pkt_count;
    double avg_time_router = (double)router_cycles / (double)pkt_count;
    printf("Average US_NIZK_Confirm cycles: %.2f (%.2f µs)\n", avg_time_confirm, avg_time_confirm / (double)tsc_hz * 1e6);
    printf("Average US_NIZK_Disavow cycles: %.2f (%.2f µs)\n", avg_time_disavow, avg_time_disavow / (double)tsc_hz * 1e6);
    printf("Average Relay processing cycles: %.2f (%.2f µs)\n", avg_time_router, avg_time_router / (double)tsc_hz * 1e6);

    close(client);
    close(serv_sock);
    return 0;
}
