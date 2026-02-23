#include "dpdk-util/eth_config2.h"
#include "main.h"
// #include "func.h"
#include "common_func.h"
#include "DPDK_func.h"

#include "groupsig/groupsig.h"
#include "groupsig/gml.h"
#include "groupsig/kty04.h"
#include "groupsig/message.h"

// OpenSSL / sockets for TLS handshake (add near other includes)
#include <arpa/inet.h>     // inet_pton
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// DPDK Crypto
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_crypto_asym.h>


// __thread EVP_MD_CTX *mdctx1 = NULL;// 署名用
// __thread EVP_MD_CTX *mdctx2 = NULL;// 検証用

// ルータ全体の処理計測用
uint64_t sender_cycles = 0;

/* ======= 固定TLS鍵とIV,AAD (handshake省略) ======= */
static const uint8_t KEY[32] = {
    0xc7,0xb5,0x68,0x7a,0xfb,0xc2,0xfc,0x4f,
    0xc8,0xf1,0x15,0xb0,0x18,0x0d,0x9d,0x26,
    0xf9,0x2c,0xf7,0x46,0xac,0xbb,0xd1,0x20,
    0x61,0x0e,0xd7,0x67,0x39,0xda,0x7e,0xbb
};

static const uint8_t FIXED_IV[12] = {
    0xf4,0x83,0x3e,0x10,0xa4,0x38,0xbf,0x13,
    0xaf,0xb0,0x1e,0x8f
};


static const uint8_t FIXED_AAD[32] = {
    0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc, 0xdd,0xee,0xff,0x00,
    0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80,
    0x90,0xa0,0xb0,0xc0, 0xd0,0xe0,0xf0,0x01
};

// 時間計測用
__thread time_t start_time;//= time(NULL); // プログラム開始時刻を記録
__thread time_t current_time;
__thread double elapsed_time;

uint64_t mcore_total_pkt_count = 0;
uint64_t total_pkt_count[CORE_NUM] = {0}; //各コアの総パケット数  

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

    // fread(buf, 1, len, f);
    size_t read_bytes = fread(buf, 1, len, f);
    fclose(f);
    if (read_bytes != (size_t)len) {
        fprintf(stderr, "Warning: expected %ld bytes, but read %zu bytes from %s\n",
                len, read_bytes, path);
    }

    groupsig_key_t *key = import_func(scheme, buf, len);
    free(buf);
    return key;
}

// Build it in SGX machine!

// size_t FRAME_SIZE = 1024;
// double TX_INTERVAL = 0.00000019;

// size_t FRAME_SIZE;
// double TX_INTERVAL;

// --- TLS key material shared between handshake and DPDK ---
static unsigned char tls_key[64];   // 32..64 bytes depending on cipher; we export max 64 bytes
static unsigned char tls_iv[16];    // IV (usually 12 bytes)
static int tls_key_len = 0;
static int tls_iv_len = 0;

// --- CryptoPMD globals used in run_forwarder ---
static struct rte_mempool *global_crypto_op_pool = NULL;
static struct rte_cryptodev_sym_session *global_sym_session = NULL;
static uint8_t global_cdev_id = 0;

size_t FRAME_SIZE;
double TX_INTERVAL;

// init for measurements

uint8_t switch_port_list[MAX_SWITCH_PORT];

struct lcore_params lcore_conf[MAX_CORE_NUM];
struct port_params port_conf[MAX_PORT];

char *app_args[256][2];


int global_sync_nb_thread = 0;
/*signal handler for conveniently stopping polling loop...*/
volatile sig_atomic_t g_flag = 0;
static void signal_handler(int signum)
{
   g_flag = 1;
}
bool slave_exit_signal = false;
bool slave_finish_signal[MAX_CORE_NUM];

static void print_port_config(uint8_t port_id)
{
   struct rte_eth_link link;
   size_t link_speed = 0;
   int ret = rte_eth_link_get_nowait(port_id, &link);
   // rte_eth_link_get_nowait(port_id, &link);
   link_speed = link.link_speed / 1000;
   printf("==========Port %d @CPU Socket %d==========\n", port_id, rte_eth_dev_socket_id(port_id));
   printf("Stat: Launched...\n");
   printf("Stat\tGbps\tRxQ No.\tTxQ No.\tRSS\n");
   if (link.link_status == ETH_LINK_DOWN)
      printf("DOWN\t");
   else
      printf("UP\t");
   printf("%zd\t%d\t%d\tIPv4 Src\n", link_speed, port_conf[port_id].nb_rxqs, port_conf[port_id].nb_txqs);
   printf("=======================================\n");
   printf("\n");
}

void print_lcore_status(uint8_t rxport, uint8_t rxq, uint8_t txport, uint8_t txq) {
   time_t t = time(NULL);
   struct tm *local = localtime(&t);
   int hour = local->tm_hour, min = local->tm_min, sec = local->tm_sec;
   struct rte_eth_link link;
   int ret = rte_eth_link_get_nowait(rxport, &link);
   printf("=========Core %d (Skt %d)==========\n", rte_lcore_id(), rte_socket_id());
   printf("Stat: Launched...@%02d:%02d:%02d\n", hour, min, sec);
   printf("Link UP?: ");
   if (link.link_status == ETH_LINK_DOWN)
      printf("DOWN\n");
   else
      printf("UP\n");
   printf("Core\tSocket\tRx Port\tRx Q\tTx Port\tTx Q\n");
   printf("%d\t%d\t%d\t%d\t%d\t%d\n", rte_lcore_id(), rte_socket_id(), rxport, rxq, txport, txq);
   printf("===========================================\n");
   printf("\n");
}

static int run_forwarder(__rte_unused void *arg)
{
	struct rte_mempool *mbuf_pool = (rte_mempool *)arg;

   // init port and queue
   uint32_t lcore_id = rte_lcore_id();
   uint8_t rxport = lcore_conf[lcore_id].rxport;
   uint8_t rxq = lcore_conf[lcore_id].rxqueue;
   uint8_t txport = lcore_conf[lcore_id].txport;
   uint8_t txq = lcore_conf[lcore_id].txqueue;

   // prepare mbuf pointers for rx/tx
   // FUTURE: allow one thread to have multiple ports and queues
   struct rte_mbuf *rx_pkt_mbuf[BURST_SIZE];
	struct rte_mbuf *tx_pkt_mbuf[BURST_SIZE];

   print_lcore_status(rxport, rxq, txport, txq);

   // sleep for avoiding simuletaneous malloc by multi-threads
   int sleep_time_ms = (global_sync_nb_thread - 1) * 100;
   printf("Stat: Sleep %d ms @ thread %d: avoiding simultaneous malloc from %d threads...\n", sleep_time_ms, rte_lcore_id(), global_sync_nb_thread);
   rte_delay_ms(sleep_time_ms);


   struct rte_ether_hdr eth_hdr;
   struct rte_ipv4_hdr ip_hdr;

   random_device seed_gen;
   mt19937 engine(seed_gen());
   std::uniform_real_distribution<> dist(0.0, 1.0);

   uint64_t n_all_tx = 0;
   uint64_t n_all_rx = 0;
   uint64_t n_all_measured = 0;
   uint64_t t_elapsed_sum = 0;
   uint64_t t_elapsed_avgsqdev_sum = 0;
   uint64_t t_latency = 0;

   uint64_t base_clock = rte_get_tsc_hz();
   uint64_t clock_start = rte_rdtsc();
   uint64_t clock_end = 0;
   //レイテンシ測定用
   uint64_t stime = 0;
   uint64_t layclock_start = 0;
   uint64_t layclock_end = 0;
   uint64_t cycles = 0;

   static double sum_cycles = 0.0;
   static double sumsq_cycles = 0.0;
   static uint64_t count_cycles = 0;

   //スループット測定用
   //    uint64_t total_pkt_count = 0;

   // TLS用初期化
   size_t offset_from_start = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);

    // ノード初期化
   //  Node nodes[NODES];
   Node *nodes = (Node *)rte_malloc(NULL, sizeof(Node) * NODES, 0);
   for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    //すべての鍵交換処理
    // レシーバと各リレーの鍵交換
    Node *me = &nodes[NODES-1];
    unsigned char sharenode[KEY_LEN];
    for (int i = 1; i < NODES - 1; i++) {
       derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
       memcpy(me->k[i], sharenode, KEY_LEN);
       // print_hex("ki", me->k[i], KEY_LEN);
    }

    // センダーと各リレーの鍵交換
    me = &nodes[0];
    for (int i = 1; i < NODES - 1; i++) {
       derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
       memcpy(me->k[i], sharenode, KEY_LEN);
       // print_hex("ki", me->k[i], KEY_LEN);
    }

    // リレーがSと鍵交換(往路)
    for (int i = 1; i < NODES - 1; i++) {
        // 共有鍵を計算
        Node *node = &nodes[i];
        derive_shared(node->dh_sk, nodes[0].dh_pk, sharenode);
        // リレーiの状態に鍵を保存
        memcpy(node->ki, sharenode, KEY_LEN);
    }
    // リレーがRと鍵交換(復路)
    for (int i = 1; i < NODES - 1; i++) {
        // 共有鍵を計算
        Node *node = &nodes[i];
        derive_shared(node->dh_sk, nodes[NODES - 1].dh_pk, sharenode);
        // リレーiの状態に鍵を保存
        memcpy(node->ki_R, sharenode, KEY_LEN);
        // printf("k%d ", i);
        // print_hex("derived ", node->k[i], KEY_LEN);
    }
      
    // pktの準備
    Packet pkt;
    unsigned char kS_pub[PUB_LEN];
    // kS_pub = load_pubkey_pem("dh_pub.pem");
    get_raw_pub(me->dh_sk, kS_pub);
    // EVP_PKEY *pub = import_x25519_pub(kS_pub);
    
    // DH共有秘密の導出
    unsigned char shared[SEC_LEN];
    derive_shared(me->dh_sk, nodes[NODES-1].dh_pk, shared);
    // EVP_PKEY_free(pub);
    
    rte_memcpy(me->sess_key, shared, KEY_LEN);
    me->has_sess = 1;
    // print_hex("C_k", me->sess_key, KEY_LEN);
    uint64_t start_cycles = rte_rdtsc();

    hash_sid(kS_pub, PUB_LEN, pkt.h.sid);
    print_hex("SID", pkt.h.sid, SID_LEN);

    //    pkt.h.status = SETUP_REQ;
    pkt.h.status = DATA_TRANS;
    pkt.h.idx = 1;  // 最初の送信先インデックス(今回はR3が最初のリレー)

    // メッセージ暗号化
    unsigned char msg[MAX_PTXT];
    size_t msg_len = MAX_PTXT;
    srand(time(NULL));

   // 任意の文字列生成部分
   for (size_t i = 0; i < msg_len; i++) {
      // 印字可能なASCII文字（32-126）をランダムに生成
      msg[i] = 32 + (rand() % 95);
   }
   //  print_hex("Plaintext message", msg, msg_len);
   //  const char *msg = "hello world";
   //  size_t msg_len = strlen(msg);

    // --- Padding Fix: 先頭にゼロブロックを付加 ---
    //256bit安全性を確保するには最低64B(512bit)のパディングが必要
    unsigned char zero_pad[PAD_LEN] = {0};

    size_t padded_len = 0;
    unsigned char *padded_msg = concat2(zero_pad, PAD_LEN,(const unsigned char*)msg, msg_len,&padded_len);
   //  print_hex("Padded message", padded_msg, padded_len);

    aead_encrypt(me->sess_key, padded_msg, padded_len, pkt.h.sid, pkt.p.iv, pkt.p.ct, pkt.p.tag);
    pkt.p.ct_len = padded_len;
   //  print_hex("Ciphertext", pkt.p.ct, pkt.p.ct_len);
    
    //センダーのMAC
    // 各リレーの共有鍵 k_i を計算 & M_i を生成
    for (int i = 1; i < ROUTERS + 1; i++) {
        // print_hex("ki", me->k[i], KEY_LEN);
        // HMACでACSEG生成
        unsigned char acseg[ACSEG_LEN];
        unsigned int acseg_len;
        size_t offset = (i - 1) * ACSEG_LEN;
        // print_hex("me->ki", me->ki, KEY_LEN);
        int gmac_result = aes_gmac(me->k[i], KEY_LEN, FIXED_IV, IV_LEN, pkt.p.ct, pkt.p.ct_len, pkt.h.acseg_concat + offset, &acseg_len);
        if (gmac_result != 0) {
            fprintf(stderr,"GMAC failed at R%d\n", i);
            return -1;
        }
      //   print_hex("ACSEG", pkt.h.acseg_concat + offset, acseg_len);
    }
   //  print_hex("ACSEG concat", pkt.h.acseg_concat, ROUTERS * ACSEG_LEN);

    // ROUTERS - 1つ目のリレーまでセットアップ要求を処理
   struct rte_mbuf *frame;

   frame = rte_pktmbuf_alloc(mbuf_pool);
   frame->pkt_len = FRAME_SIZE - 16;
   frame->data_len = FRAME_SIZE - 16;

   // Eth header
   eth_hdr.ether_type = rte_bswap16(RTE_ETHER_TYPE_IPV4);
   rte_memcpy(rte_pktmbuf_mtod(frame, struct ether_hdr*), &eth_hdr, sizeof(struct rte_ether_hdr));
   
   // IP header
   ip_hdr.version_ihl = 0x45;
   ip_hdr.next_proto_id = 200;
   ip_hdr.total_length = rte_bswap16(FRAME_SIZE - 14);
   ip_hdr.src_addr = engine();
   rte_memcpy(rte_pktmbuf_mtod_offset(frame, struct ipv4_hdr*, sizeof(struct rte_ether_hdr)), &ip_hdr, sizeof(struct rte_ipv4_hdr));

   // print_hex("τ0", pkt.p.tau, SIG_LEN);
   size_t wire_len = build_overlay_data_trans(frame, &pkt);
   uint64_t end_cycles = rte_rdtsc();
   sender_cycles += end_cycles - start_cycles;
   printf ("Overlay length: %zu bytes\n", wire_len);   
   // printf("Build overlay data trans took %lu cycles\n", end_cycles - start_cycles);


   for (int rep = 1; rep < ROUTERS; rep++) {
      if (router_handle_data_trans(frame, nodes) == 0) {
         printf("Router: data packets transmit to node %d\n", nodes[rep].id);
      } else {
         printf("Router: data packets transmit to node %d\n", nodes[rep].id);
      }
   }
   unsigned char *fm = rte_pktmbuf_mtod(frame, unsigned char*);
   
   if (parse_frame_to_pkt(fm, frame->pkt_len, &pkt) != 0) {
      fprintf(stderr, "parse failed\n");
      return -1;
   }
      
   start_time = time(NULL); // プログラム開始時刻を記録
   for (int kk = 0; ; ++kk)
   {
      if (slave_exit_signal == true)
         break;
      current_time = time(NULL); // 現在時刻を取得
      elapsed_time = difftime(current_time, start_time);
      if (elapsed_time >= 15.0) {
          // slave_exit_signal = true;
          break;
      }
      bool warmup = (elapsed_time < 5.0);
      // RX
      // printf("Received packet"); 
      size_t nb_rx = rte_eth_rx_burst(rxport, rxq, rx_pkt_mbuf, BURST_SIZE);
      if (nb_rx > 0) {
         //   if (n_all_rx >= 1000) {
            //             printf("Reached 100000 packets, stopping...\n");
            //         break;
            //     }
            //  clock_end = rte_rdtsc();
         // printf("Received packet");
         for (int i = 0; i < nb_rx; i++)
         {
            // 受信したパケットに対する処理
            layclock_end = rte_rdtsc();
            // printf("\n2\n");
            // printf("layclock_end: %lu\n", layclock_end);

            uint8_t *ptr = rte_pktmbuf_mtod(rx_pkt_mbuf[i], uint8_t*);
            size_t off = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
            size_t total_len = rx_pkt_mbuf[i]->pkt_len;

            // size_t ct_len = total_len - 16;  // 最後の 16 バイトは TAG
            size_t wire_len = 80 + (ROUTERS * ACSEG_LEN) + MAX_PTXT;//6789//total_len - off - 16; // (オーバレイ部分今回はべた書き)
            uint8_t *ctr = ptr + off;
            uint8_t *tag_ptrr = ptr + total_len - 16;//ptr + off + wire_len;
            uint8_t pt_out[FRAME_SIZE];  // 十分大きく

            // int ok = aead_decrypt(KEY, ctr, wire_len, FIXED_AAD, FIXED_IV, tag_ptrr, pt_out);

            // if (!ok) {
            //    printf("Decrypt FAIL\n");
            //    rte_pktmbuf_free(rx_pkt_mbuf[i]);
            //    continue;
            // }

            // // 復号成功 → mbuf に平文を戻す
            // rte_memcpy(ctr, pt_out, wire_len);
            // rx_pkt_mbuf[i]->pkt_len -= 16;
            // rx_pkt_mbuf[i]->data_len -= 16;
            // // printf("Decrypt OK - pkt_len now %u\n", rx_pkt_mbuf[i]->pkt_len);

            // unsigned char *frame = rte_pktmbuf_mtod(rx_pkt_mbuf[i], unsigned char*);
            // size_t frame_len = rx_pkt_mbuf[i]->pkt_len;
            // Packet pkt;
            // if (parse_frame_to_pkt(frame, frame_len, &pkt) != 0) {
            //     fprintf(stderr, "Router: parse failed\n");
            //     return -1;
            // }
            
            // printf("Packet parsed: frame_len=%zu, status=%d, idx=%d\n", frame_len, pkt.h.status, pkt.h.idx);
            // rte_memcpy(&layclock_start, pkt.p.stime, sizeof(uint64_t));
            // // printf("stime: %lu\n", stime);
            // // printf("layclock_start: %lu\n", layclock_start); 
            // cycles = layclock_end - layclock_start;
            // printf("latency: %.2f\n", (double)cycles / base_clock ); // µs
            // if (frame_len == 1008) { // 自分が送ったパケットの応答のみレイテンシ測定
            //     // printf("layclock_cycles: %lu\n", cycles);
            //     // t_latency += cycles;
            //     // total_pkt_count++;
            //     // 統計更新
            //     sum_cycles += (double)cycles;
            //     sumsq_cycles += (double)cycles * (double)cycles;
            //     count_cycles++;
                
            //     // if (count_cycles > 30) { // サンプル数が十分にあるときだけ外れ値判定
            //     //     double mean = sum_cycles / count_cycles;
            //     //     double var = (sumsq_cycles / count_cycles) - (mean * mean);
            //     //     double stddev = sqrt(var);
                    
            //     //     if ((cycles >= mean - 2 * stddev) && (cycles <= mean + 2 * stddev)) {
            //     //         // printf("layclock_cycles: %lu\n\n", cycles);
            //     //         // 外れ値でなければ加算
            //     //         // print_hex("π", pkt.h.pi_concat, 64);
            //     //         t_latency += cycles;
            //     //         total_pkt_count[lcore_id]++;
            //     //     } else {
            //     //         // printf("outlier ignored: %lu cycles (mean=%.2f, std=%.2f)\n",
            //     //         //     cycles, mean, stddev);
            //     //     }
            //     // } else {
            //     //     // 初期サンプルは外れ値判定せずに加算
            //     //     t_latency += cycles;
            //     //     total_pkt_count[lcore_id]++;
            //     // }
            //     t_latency += cycles;
            //     total_pkt_count[lcore_id]++;
                
            // }
            rte_pktmbuf_free(rx_pkt_mbuf[i]);
         }
         //   n_all_rx += nb_rx;
         if (!warmup) {
            n_all_rx += nb_rx;
            total_pkt_count[lcore_id]+=nb_rx;
         }

      }      

      // Determine #packets to transmit
      clock_end = rte_rdtsc();
      double f_tx_burst = min((clock_end - clock_start) / (TX_INTERVAL * base_clock), (double)BURST_SIZE);
      uint32_t tx_burst;

      if ((double)(engine()) < UINT32_MAX * (f_tx_burst - (int)f_tx_burst))
         tx_burst = (int)f_tx_burst + 1;
      else
         tx_burst = (int)f_tx_burst;
      clock_start = clock_end;

      // TX
      for (int i = 0; i < tx_burst; ++i) {

         // 送信パケットの作成

         tx_pkt_mbuf[i] = rte_pktmbuf_alloc(mbuf_pool);
         tx_pkt_mbuf[i]->pkt_len = FRAME_SIZE;
         tx_pkt_mbuf[i]->data_len = FRAME_SIZE;

         // Eth header
         eth_hdr.ether_type = rte_bswap16(RTE_ETHER_TYPE_IPV4);
         rte_memcpy(rte_pktmbuf_mtod(tx_pkt_mbuf[i], struct ether_hdr*), &eth_hdr, sizeof(struct rte_ether_hdr));

         // IP header
         ip_hdr.version_ihl = 0x45;
         ip_hdr.next_proto_id = 200;
         ip_hdr.total_length = rte_bswap16(FRAME_SIZE - 14);
         ip_hdr.src_addr = engine();
         rte_memcpy(rte_pktmbuf_mtod_offset(tx_pkt_mbuf[i], struct ipv4_hdr*, sizeof(struct rte_ether_hdr)), &ip_hdr, sizeof(struct rte_ipv4_hdr));



         // 往路のOverlay header + payload
        //  printf("=== R0 (Sender) lcore %d ===\n", lcore_id);
         // print_hex("τ0", pkt.p.tau, SIG_LEN);
        //  stime = rte_rdtsc();
        //  rte_memcpy(pkt.p.stime, &stime, sizeof(uint64_t));
        //  printf ("Embed send time: %lu\n", *(uint64_t*)pkt.p.stime);
        //  size_t wire_len = build_overlay_setup_req(tx_pkt_mbuf[i], &pkt);
        size_t wire_len = build_overlay_data_trans(tx_pkt_mbuf[i], &pkt);
        
        // ===== AES-GCM ENCRYPT (OpenSSL) =====
        // overlay の開始アドレス（暗号化対象）
        size_t off = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
        unsigned char *overlay_ptr = rte_pktmbuf_mtod_offset(tx_pkt_mbuf[i], unsigned char *, off);
        unsigned char *ct = overlay_ptr;  // 上書きする
        uint8_t tag[16];
        uint8_t iv[12];
         // memcpy(iv, FIXED_IV, 12);_
         aead_encrypt(KEY, overlay_ptr, wire_len, FIXED_AAD, iv, ct, tag);
         // print_hex("Encrypted overlay", ct, wire_len);
         // print_hex("GCM tag", tag, 16);
         // print_hex("GCM IV", iv, 12);
         // printf("Packet: %d bytes (overlay: %zu bytes)\n", tx_pkt_mbuf[i]->pkt_len, wire_len);
         // ===== TAG を末尾に付加 =====
         char *tag_ptr = rte_pktmbuf_append(tx_pkt_mbuf[i], 16);
         if (tag_ptr == NULL) {
            printf("ERROR: Not enough tailroom for TAG append\n");
            rte_pktmbuf_free(tx_pkt_mbuf[i]);
            continue;
         }
         memcpy(tag_ptr, tag, 16);
         // print_hex("TAG", tag, 16);
         // printf("Packet: %d bytes (overlay: %zu bytes)\n", tx_pkt_mbuf[i]->pkt_len, wire_len);
      }


      uint16_t nb_tx = rte_eth_tx_burst(txport, txq, tx_pkt_mbuf, tx_burst);
      // printf("DEBUG TX: requested=%u, sent=%u, txport=%u txq=%u\n", tx_burst, nb_tx, txport, txq);
      if (unlikely(nb_tx < tx_burst))
      {
         for (size_t j = nb_tx; j < tx_burst; j++)
            rte_pktmbuf_free(tx_pkt_mbuf[j]);
      }
      // n_all_tx += nb_tx;
      if (!warmup) {
        n_all_tx += nb_tx;
      }

   }


   // EVP_MD_CTX_free(mdctx1);
   // EVP_MD_CTX_free(mdctx2);
   finish:
   rte_delay_ms(rte_lcore_id() * 100);
   
   printf("\n=================\n");
   printf("lcore %d RX: %ld, TX: %ld (%.4f)\n", lcore_id, n_all_rx, n_all_tx, (double)n_all_rx / n_all_tx);
//    printf("lcore %d measured: %ld (%.4f)\n", lcore_id, n_all_measured, (double)n_all_measured / n_all_rx);
//    printf("lcore %d avg: %lf [ns], mv_std: %lf [ns]\n", lcore_id, (double)t_elapsed_sum / n_all_measured, sqrt((double)t_elapsed_avgsqdev_sum / n_all_measured));
    // レイテンシ計算
    // double avg_cycles = (double)t_latency / (double)total_pkt_count;
    // printf("Average cycles per packet: %.2f\n", avg_cycles);
    // double avg_time = avg_cycles / (double)base_clock;
    // printf("Average time per packet: %.2f μs\n", avg_time * 1e6);
    //サイクル数
   //  double avg_time = (double)sender_cycles / (double)base_clock;
   printf("Base clock: %lu\n", base_clock);
   printf("Sender total cycles: %lu, avg time per packet: %.2f μs\n", sender_cycles, (double)sender_cycles / (double)base_clock * 1e6);

   //  // スループット計算
   //  double total_elapsed_sec = 10.0;//(double)t_latency / (double)base_clock;
   //  double total_bits = (double)n_all_rx * (double)FRAME_SIZE * 8.0;
   // //  double total_bits = (double)total_pkt_count[lcore_id] * 4096.0 * 8.0;
   // double total_mbps = total_elapsed_sec > 0 ? (total_bits / total_elapsed_sec) / 1e9 : 0.0;
   //  printf("lcore %d: total pkts=%" PRIu64 ", avg throughput=%.3f Gbps over %.2f s\n",
   //         lcore_id, total_pkt_count[lcore_id], total_mbps, total_elapsed_sec);

    // printf("lcore %d: total pkts=%" PRIu64 "\n", lcore_id, total_pkt_count[lcore_id]);
    mcore_total_pkt_count += total_pkt_count[lcore_id];

   slave_finish_signal[lcore_id] = true;
   return 0;
}



int main(int argc, char *argv[])
{
   uint8_t i = 0;
   // interpret cmdline config
   char *qargv = NULL, *opargv = NULL;

   int args_cnt = 0;
   for (i = 0; i < argc; i++)
   {
      if (strcmp(argv[i], "--userset") == 0)
      {
         qargv = argv[++i];
      }
      else if (strcmp(argv[i], "--help") == 0)
      {
         printf("help\n");
         exit(1);
      }
      else if (strcmp(argv[i], "--tx_rate") == 0) 
      {
         opargv = argv[++i];
         size_t tmp;
         if (1 == sscanf(opargv, "%zu", &tmp)){
            double tmp_interval = 1 / (double)tmp;
            TX_INTERVAL = tmp_interval;
         }
      }
      else if (strcmp(argv[i], "--frame_size") == 0)
      {
         opargv = argv[++i];
         size_t tmp;
         if (1 == sscanf(opargv, "%zu", &tmp)){
            FRAME_SIZE = tmp;
         }
      }
      else if (strncmp(argv[i], "--", 2) == 0)
      {
         app_args[args_cnt][0] = (char *)malloc(sizeof(char) * (strlen(argv[i]) + 1));
         strcpy(app_args[args_cnt][0], argv[i]);

         if (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0)
         {
            i++;
            app_args[args_cnt][1] = (char *)malloc(sizeof(char) * (strlen(argv[i]) + 1));
            strcpy(app_args[args_cnt][1], argv[i]);
         }
         else
         {
            app_args[args_cnt][1] = NULL;
         }

         args_cnt++;
      }
   }
   app_args[args_cnt][0] = NULL;

   if (qargv == NULL)
   {
      printf("userset arg not defined\n");
      exit(1);
   }

   parse_config(qargv, port_conf, lcore_conf);
   int ret = rte_eal_init(argc, argv);
   if (ret < 0)
      rte_exit(0, "Eal could not be initialized\n");

   /*
   allocate pktmbuf for rx and tx queues.
   should carefully consider numa sockets
   */
   size_t wanted_data_room = FRAME_SIZE + RTE_PKTMBUF_HEADROOM;
   // size_t wanted_data_room = FRAME_SIZE + RTE_PKTMBUF_HEADROOM + 36;
   struct rte_mempool *pkt_pool0, *pkt_pool1;
   pkt_pool0 = rte_pktmbuf_pool_create("PKT_POOL0", // mempool name
                                       NUM_MBUFS,   // number_of_elements *2^q -1 is optimal
                                       256,         // cache_size
                                       0,           // prive_data
                                       1670,
                                       0); // socket_id

   // pkt_pool1 = rte_pktmbuf_pool_create("PKT_POOL1", // mempool name
   //                                     NUM_MBUFS,   // number_of_elements *2^q -1 is optimal
   //                                     256,         // cache_size
   //                                     0,           // prive_data
   //                                     RTE_MBUF_DEFAULT_BUF_SIZE,
   //                                     1); // socket_id

   if (pkt_pool0 == NULL)
      rte_exit(0, "Mempool0 could not be initialized\n");
   // if (pkt_pool1 == NULL)
   //   rte_exit(0, "Mempool1 could not be initialized\n");


    
    // set up NIC ports
    for (i = 0; i < MAX_PORT; i++)
   {
      if ((port_conf[i].nb_rxqs != 0) | (port_conf[i].nb_txqs != 0))
      {
         if (rte_eth_dev_socket_id(i) == 0)
         {
            port_init(i, pkt_pool0, port_conf);
         }
         if (rte_eth_dev_socket_id(i) == 1)
         {
            printf("!! socket #1 is used\n");
            // port_init(i, pkt_pool1, port_conf);
         }
      }
   }

   // Set source IPv4 address for RSS hash's input.
   for (i = 0; i < MAX_PORT; i++)
   {
      if (port_conf[i].nb_rxqs != 0)
      {
         init_rss_ipv4src(i);
      }
   }

   for (i = 0; i < MAX_PORT; i++)
   {
      if (port_conf[i].nb_rxqs != 0)
         print_port_config(i);
   }

   // launch forwarder thread on core.
   uint8_t lcore_id;
   RTE_LCORE_FOREACH_SLAVE(lcore_id)
   {
      if (lcore_conf[lcore_id].en == 1)
      {
         printf("enabled lcore: %d\n", lcore_id);
         slave_finish_signal[lcore_id] = false;

         global_sync_nb_thread++;
         if (rte_eth_dev_socket_id(lcore_conf[lcore_id].rxport) == 0)
         {
            rte_eal_remote_launch(run_forwarder, pkt_pool0, lcore_id);
         }
         else if (rte_eth_dev_socket_id(lcore_conf[lcore_id].rxport) == 1)
         {
            printf("!! socket #1 is used\n");
         }
         else
         {
            printf("Error: No CPU socket exists...\n");
            printf("%d\n", lcore_id);
            exit(1);
         }
      }
      else
      {
         printf("disabled lcore: %d\n", lcore_id);
      }
   }

   signal(SIGINT, signal_handler);

   while (!g_flag)
   { // launch master process
      bool is_finished = true;
      RTE_LCORE_FOREACH_SLAVE(lcore_id)
         if (lcore_conf[lcore_id].en == 1)
            is_finished &= slave_finish_signal[lcore_id];
      
      if (is_finished)
         break;
   }
   slave_exit_signal = true;

   for (i = 0; i < MAX_PORT; i++)
   {

      if (port_conf[i].nb_rxqs != 0)
      {
         struct rte_eth_stats eth_stats;
         rte_eth_stats_get(i, &eth_stats);

         double iratio = (double)eth_stats.ipackets / (eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors);
         // printf("Port %d: ipkts %zd, imiss %zd, ierr %zd (%lf), rx_nombuf %ld\n", i, eth_stats.ipackets, eth_stats.imissed, eth_stats.ierrors, iratio, eth_stats.rx_nombuf);

      }
   }


   for (int i = 0; i < CORE_NUM; ++i) {
      //   printf("lcore %d: total pkts=%" PRIu64 "\n", i, total_pkt_count[i]);
    }

   // スループット計算
    double total_elapsed_sec = 10.0;//(double)t_latency / (double)base_clock;
    // double total_bits = (double)total_pkt_count * 1024.0 * 8.0;
    double total_bits = (double)mcore_total_pkt_count * (double)FRAME_SIZE * 8.0;
    double total_mbps = (total_bits / total_elapsed_sec) / 1e6;
   printf("total pkts=%" PRIu64 ", avg Throughput=%.3f Mbps over %.2f s\n",
           mcore_total_pkt_count, total_mbps, total_elapsed_sec);
   
   // グッドプット計算
   double total_pbits = (double)mcore_total_pkt_count * (double)MAX_PTXT * 8.0;
    double total_pmbps = (total_pbits / total_elapsed_sec) / 1e6;
   printf("total pkts=%" PRIu64 ", avg Goodput=%.3f Mbps over %.2f s\n",
           mcore_total_pkt_count, total_pmbps, total_elapsed_sec);

   sleep(1);
}
