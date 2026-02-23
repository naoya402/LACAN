#include "dpdk-util/eth_config2.h"
#include "main.h"
// #include "func.h"
#include "common_func.h"
#include "DPDK_func.h"
#include "rte_security.h"

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
#include <rte_net.h>  

groupsig_key_t *grpkey;
groupsig_key_t *mgrkey;
groupsig_key_t *memkey;
gml_t *gml;
crl_t *crl;
groupsig_signature_t *sig;
message_t *gsm;

// リレー全体の処理計測用
__thread uint64_t router_cycles = 0;
// uint64_t router_cycles = 0;
/* スレッドローカルの FILE* を使う（各 lcore ごとに独立したファイルを開く） */
static __thread FILE *router_cycle_fp = NULL;

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

// 32 bytes AAD
static const uint8_t FIXED_AAD[32] = {
    0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
    0x99,0xaa,0xbb,0xcc, 0xdd,0xee,0xff,0x00,
    0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80,
    0x90,0xa0,0xb0,0xc0, 0xd0,0xe0,0xf0,0x01
};

unsigned char ts[4] = {0, 1, 2, 3};

// size_t FRAME_SIZE = 1024;
// double TX_INTERVAL = 0.00000019;

// --- TLS key material shared between handshake and DPDK ---
static unsigned char tls_key[64];   // 32..64 bytes depending on cipher; we export max 64 bytes
static unsigned char tls_iv[16];    // IV (usually 12 bytes)
static int tls_key_len = 0;
static int tls_iv_len = 0;

// --- CryptoPMD globals used in run_forwarder ---
static struct rte_mempool *global_crypto_op_pool = NULL;
static struct rte_cryptodev_sym_session *global_sym_session_enc = NULL;
static struct rte_cryptodev_sym_session *global_sym_session_dec = NULL;
static uint8_t global_cdev_id = 0;

// IV/TAG プール
// static struct rte_mempool *iv_pool = NULL;
// static struct rte_mempool *tag_pool = NULL;
#define IV_TAG_POOL_SIZE 2048

static struct rte_mempool *iv_pool = NULL;
static struct rte_mempool *tag_pool = NULL;


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


void log_router_cycles(uint64_t cycles)
{
    if (router_cycle_fp == NULL) {
        /* lcore id を取得して per-lcore ファイルを作る */
      //   unsigned lcore = rte_lcore_id()
       int Input_rate = 100;
        char fname[128];
        int n = snprintf(fname, sizeof(fname), "/router_cycles/router_cycles_1322B_%d%%.csv", Input_rate);
        (void)n;
        router_cycle_fp = fopen(fname, "w");
        if (router_cycle_fp == NULL) {
            /* 失敗しても処理は続けられるようにする */
            perror("fopen router_cycles file");
            return;
        }
    }

    /* 1行に 1 サンプル（テキスト）を追記 */
    fprintf(router_cycle_fp, "%" PRIu64 "\n", cycles);

    /* 即時保存を優先するなら fflush。性能優先ならコメントアウトしてよい。 */
   //  fflush(router_cycle_fp);
}


//マルチスレッド対応版 初期化処理（各スレッドで一度だけ呼び出す）
void init_groupsig_once() {
   // printf("Initializing group signature scheme...\n");
      groupsig_init(GROUPSIG_KTY04_CODE, time(NULL));
      grpkey = load_key_from_file("grpkey.pem", GROUPSIG_KTY04_CODE, groupsig_grp_key_import);
      mgrkey = load_key_from_file("mgrkey.pem", GROUPSIG_KTY04_CODE, groupsig_mgr_key_import);
      memkey = load_key_from_file("memkey.pem", GROUPSIG_KTY04_CODE, groupsig_mem_key_import);
      printf("Loaded grpkey, mgrkey, memkey from files.\n");
      // gml読み込み
      FILE *fgml = fopen("gml.dat", "rb");
      if (!fgml) die("fopen gml.dat");
      fseek(fgml, 0, SEEK_END);
      size_t gml_len = ftell(fgml);
      fseek(fgml, 0, SEEK_SET);
      unsigned char *gml_buf = (unsigned char *)malloc(gml_len);
      if (!gml_buf) die("malloc gml_buf");
      if (fread(gml_buf, 1, gml_len, fgml) != gml_len) {
         fprintf(stderr, "Error reading SID\n");
      }
      fclose(fgml);
      gml = gml_import(GROUPSIG_KTY04_CODE, gml_buf, gml_len);
      free(gml_buf);
      crl = crl_init(GROUPSIG_KTY04_CODE);
      printf("Loaded gml and crl files.\n");


      // Setup (new group)
      groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

      printf("Generating group signature for public key...\n"); 
   
   // グループ署名
   EVP_PKEY *sk = load_seckey_pem("dh_sec.pem");
      unsigned char kS_pub[PUB_LEN];
      get_raw_pub(sk, kS_pub);
      size_t tsconcat_len;
      unsigned char *tsconcat = concat2(kS_pub, PUB_LEN, ts, 4, &tsconcat_len);
      gsm = message_from_bytes(tsconcat, tsconcat_len);
      free(tsconcat);
      sig = groupsig_signature_init(GROUPSIG_KTY04_CODE);
   //  groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);
      // rte_spinlock_lock(&groupsig_lock);
   groupsig_sign(sig, gsm, memkey, grpkey, UINT_MAX);
   // rte_spinlock_unlock(&groupsig_lock);
      char *strsig = groupsig_signature_to_string(sig);
   //  printf("sig: %s\n", strsig);
      free(strsig);
      printf("Group signature generated.\n");
}
   
static void init_crypto_pools(void) {
      // IV用プール（12バイト）
      iv_pool = rte_mempool_create("IV_POOL",
         IV_TAG_POOL_SIZE,
         16,  // 12バイトだがアライメントで16
         256,
         0,
         NULL, NULL, NULL, NULL,
         rte_socket_id(),
         0);
      
      // Tag用プール（16バイト）
      tag_pool = rte_mempool_create("TAG_POOL",
         IV_TAG_POOL_SIZE,
         16,
         256,
         0,
         NULL, NULL, NULL, NULL,
         rte_socket_id(),
         0);
      
      if (!iv_pool || !tag_pool)
         rte_exit(EXIT_FAILURE, "Failed to create IV/TAG pools\n");
}

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

// enum role_t { ROLE_CLIENT, ROLE_SERVER } role = ROLE_CLIENT;

static int run_forwarder(__rte_unused void *arg)
{
   // printf("Entering main loop on lcore\n");
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;

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

   uint64_t n_all_tx = 0;
   uint64_t n_all_rx = 0;
   uint64_t test_rx = 0;
   uint64_t n_all_measured = 0;
   uint64_t t_elapsed_sum = 0;
   uint64_t t_elapsed_avgsqdev_sum = 0;

 // ノード初期化(復路)
//  printf("Initializing nodes...\n");
   // Node nodes[NODES];
   // メモリ確保 (ソケットIDは現在のlcoreのものを使用)
   Node *nodes = (Node *)rte_malloc(NULL, sizeof(Node) * NODES, 0);
   if (nodes == NULL) {
      printf("Failed to allocate memory for nodes\n");
      return -1;
   }
   for (int i=0;i<NODES;i++) {
        node_init(&nodes[i], i, router_addresses[i]);
    }

    //すべての鍵交換処理
    // レシーバと各リレーの鍵交換
    Node *me = &nodes[NODES-1];
    unsigned char sharenode[KEY_LEN];
    for (int i = 1; i < NODES - 1; i++) {
       derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
       rte_memcpy(me->k[i], sharenode, KEY_LEN);
       // print_hex("ki", me->k[i], KEY_LEN);
    }

    // センダーと各リレーの鍵交換
    me = &nodes[0];
    for (int i = 1; i < NODES - 1; i++) {
       derive_shared(me->dh_sk, nodes[i].dh_pk, sharenode);
       rte_memcpy(me->k[i], sharenode, KEY_LEN);
       // print_hex("ki", me->k[i], KEY_LEN);
    }

    // リレーがSと鍵交換(往路)
    for (int i = 1; i < NODES - 1; i++) {
        // 共有鍵を計算
        Node *node = &nodes[i];
        derive_shared(node->dh_sk, nodes[0].dh_pk, sharenode);
        // リレーiの状態に鍵を保存
        rte_memcpy(node->ki, sharenode, KEY_LEN);
    }
    // リレーがRと鍵交換(復路)
    for (int i = 1; i < NODES - 1; i++) {
        // 共有鍵を計算
        Node *node = &nodes[i];
        derive_shared(node->dh_sk, nodes[NODES - 1].dh_pk, sharenode);
        // リレーiの状態に鍵を保存
        rte_memcpy(node->ki_R, sharenode, KEY_LEN);
        // printf("k%d ", i);
        // print_hex("derived ", node->k[i], KEY_LEN);
    }

    //  SID を計算
    unsigned char kS_pub[PUB_LEN];
    get_raw_pub(nodes[0].dh_sk, kS_pub);
    unsigned char sid[SID_LEN];
    hash_sid(kS_pub, PUB_LEN, sid);
    print_hex("SID(S)=H(kC)", sid, SID_LEN);

   // 受信側で τ_ROUTERSを生成(復路の検証用&通報用)
   Node *nod = &nodes[ROUTERS];
   unsigned char t[SIG_LEN];
   size_t t_len = SIG_LEN, g_len, g2_len;
   unsigned char sta_next_addr[4], sta_nnext_addr[4];
   rte_memcpy(sta_next_addr, nodes[ROUTERS + 1].addr, sizeof(sta_next_addr));
   rte_memcpy(sta_nnext_addr, nod->addr, sizeof(sta_nnext_addr));
   // τ_ROUTERS用のデータ
   unsigned char *g = concat2(sid, SID_LEN, sta_next_addr, 4, &g_len);
   unsigned char *g2 = concat2(g, g_len, sta_nnext_addr, 4, &g2_len);
   // print_hex("g for τ_ROUTERS", g, g_len);
   sign_data(nod->sk, g2, g2_len, t, &t_len);
   free(g);
   free(g2);
    unsigned char temp_rand[4] = {0x11, 0x11, 0x11, 0x11};
    for (int i=0; i < MAX_STATE - 1; i++) {
        state_set(nod, sid, nodes[ROUTERS - 1].addr, nodes[ROUTERS + 1].addr, nod->addr, t, temp_rand);
      //   printf("R3 state %d set\n", i);
    }
   // printf("R3 state set\n");
    for (int kk = 0; ; ++kk)
   {
        if (slave_exit_signal == true)
            break;
        // RX
        size_t nb_rx = rte_eth_rx_burst(rxport, rxq, rx_pkt_mbuf, BURST_SIZE);
      //   printf ("Received %zu packets on port %d\n", nb_rx, rxport);
        if (nb_rx > 0) {
            // if (n_all_rx >= 10000) {
            //    printf("Reached 1000000 packets, stopping...\n");
            //     break;
            // }
            // test_rx += nb_rx;
            for (int i = 0; i < nb_rx; i++)
            {
               struct rte_mbuf *m = rx_pkt_mbuf[i];
               // 既存の処理開始
               //  puts("\n=========================================");
               uint8_t *ptr = rte_pktmbuf_mtod(rx_pkt_mbuf[i], uint8_t*);
               size_t off = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
               size_t total_len = rx_pkt_mbuf[i]->pkt_len;
               
               // size_t ct_len = total_len - 16;  // 最後の 16 バイトは TAG
               size_t wire_len = 80 + (ROUTERS * ACSEG_LEN) + MAX_PTXT;// (オーバレイ部分今回はべた書き)
               // size_t wire_len = 6057 + 18 + 40 * (ROUTERS + 1) + (ROUTERS - 1) * 97 + 266;
               // printf("Packet: %d bytes (overlay: %zu bytes)\n", rx_pkt_mbuf[i]->pkt_len, wire_len);
               uint64_t start = rte_rdtsc();
               uint8_t *ctr = ptr + off;
               uint8_t *tag_ptrr = ptr + total_len - 16;//ptr + off + wire_len;
               uint8_t pt_out[wire_len];  // 十分大きく

               // print_hex("Tag", tag_ptrr, 16);
               // print_hex("IV", FIXED_IV, 12);

               int ok = aead_decrypt(KEY, ctr, wire_len, FIXED_AAD, FIXED_IV, tag_ptrr, pt_out);
               if (!ok) {
                  printf("Decrypt FAIL\n");
                  rte_pktmbuf_free(rx_pkt_mbuf[i]);
                  continue;
               }

               // 復号成功 → mbuf に平文を戻す
               rte_memcpy(ctr, pt_out, wire_len);
               rx_pkt_mbuf[i]->pkt_len -= 16;
               rx_pkt_mbuf[i]->data_len -= 16;
               // printf("Decrypt OK - pkt_len now %u\n", rx_pkt_mbuf[i]->pkt_len);

               // //パケット長チェック
               if (rx_pkt_mbuf[i]->pkt_len < (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + SID_LEN +  2)) {
                  //  printf("Packet too short: %d bytes\n", rx_pkt_mbuf[i]->pkt_len);
                  //  rte_pktmbuf_free(rx_pkt_mbuf[i]);
                   continue;  // パケット破棄
               }
               //  printf("Processing packet %d/%zu\n", i+1, nb_rx);
                if (router_handle_data_trans(rx_pkt_mbuf[i], nodes) == 0) {//本来は転送先を返す
                  //   printf("R3: data_trans success\n");
                } else if (router_handle_forward(rx_pkt_mbuf[i], nodes) == 0) {
                  //   printf("R3: forward success\n");
                } 
               // router_handle_data_trans(rx_pkt_mbuf[i], nodes);
               
               //  ===== AES-GCM ENCRYPT (OpenSSL) =====
               // unsigned char *pt = rte_pktmbuf_mtod(rx_pkt_mbuf[i], unsigned char*);
               // size_t pt_len = rx_pkt_mbuf[i]->pkt_len;
               
               
               unsigned char *overlay_ptr = rte_pktmbuf_mtod_offset(rx_pkt_mbuf[i], unsigned char *, off);
               
               unsigned char *ctt = overlay_ptr;  // 上書きする
               uint8_t tag[16];
               uint8_t iv[12];
               // // rte_memcpy(iv, FIXED_IV, 12);_
               aead_encrypt(KEY, overlay_ptr, wire_len, FIXED_AAD, iv, ctt, tag);
               // ===== TAG を末尾に付加 =====
               char *tag_ptrt = rte_pktmbuf_append(rx_pkt_mbuf[i], 16);
               // if (tag_ptrt == NULL) {
                  //    printf("ERROR: Not enough tailroom for TAG append\n");
                  //    rte_pktmbuf_free(rx_pkt_mbuf[i]);
                  //    continue;
                  // }
               rte_memcpy(tag_ptrt, tag, 16);
               uint64_t end = rte_rdtsc();
               uint64_t cycles = end - start;
               router_cycles += cycles;
               // printf("%" PRIu64 "\n", end-start);
               // if (n_all_rx > 100) { // ウォームアップ後に計測
               //    if (cycles > 1000 && cycles < 20000) { // 異常値除去
               //       log_router_cycles(cycles);
               //    }
               // }
            }
            n_all_rx += nb_rx;


            uint16_t nb_tx = rte_eth_tx_burst(txport, txq, rx_pkt_mbuf, nb_rx);
            if (unlikely(nb_tx < nb_rx))
            {
                for (size_t j = nb_tx; j < nb_rx; j++)
                    rte_pktmbuf_free(rx_pkt_mbuf[j]);
            }
            // n_all_rx += nb_rx;
            n_all_tx += nb_tx;
        }      
   }
   //  EVP_MD_CTX_free(mdctx1);
   //  EVP_MD_CTX_free(mdctx2);
   //  groupsig_signature_free(sig);
   //  message_free(gsm);

   rte_delay_ms(rte_lcore_id() * 100);
   // // 1. EVP_PKEY解放
   // if (sk) {
   //    EVP_PKEY_free(sk);
   //    printf("Core %d: EVP_PKEY freed\n", lcore_id);
   // }
   
   // 2. EVP_MD_CTX解放
   if (mdctx1) {
      EVP_MD_CTX_free(mdctx1);
      printf("Core %d: mdctx1 freed\n", lcore_id);
   }
   if (mdctx2) {
      EVP_MD_CTX_free(mdctx2);
      printf("Core %d: mdctx2 freed\n", lcore_id);
   }
   
   // // 3. グループ署名関連（個別リソースのみ）
   // if (sig) {
   //    groupsig_signature_free(sig);
   //    printf("Core %d: signature freed\n", lcore_id);
   // }
   // if (gsm) {
   //    message_free(gsm);
   //    printf("Core %d: message freed\n", lcore_id);
   // }
   
   printf("\n=================\n");
   printf("test_rx: %ld\n", test_rx);
   printf("lcore %d RX: %ld, TX: %ld (%.4f)\n", lcore_id, n_all_rx, n_all_tx, (double)n_all_rx / n_all_tx);
   printf("lcore %d measured: %ld (%.4f)\n", lcore_id, n_all_measured, (double)n_all_measured / n_all_rx);
//    printf("lcore %d avg: %lf [ns], mv_std: %lf [ns]\n", lcore_id, (double)t_elapsed_sum / n_all_measured, sqrt((double)t_elapsed_avgsqdev_sum / n_all_measured));

    // サイクル換算
    // グローバル変数から平均を計算
   double avg_verify_tau = (double)for_verify_tau_cycles / n_all_rx;
   double avg_verify_pi = (double)for_verify_pi_cycles / n_all_rx;
   double avg_com_c = (double)for_com_c_cycles / n_all_rx;
   double avg_sign_pi = (double)for_sign_pi_cycles / n_all_rx;
   double avg_conf_v = (double)for_conf_v_cycles / n_all_rx;
   double avg_sign_tau = (double)for_sign_tau_cycles / n_all_rx;

   double avg_datatrans_gen_acseg = (double)datatrans_gen_acseg_cycles / n_all_rx;
   double avg_datatrans_verify_acseg = (double)datatrans_verify_acseg_cycles / n_all_rx;

   double avg_router = (double)router_cycles / n_all_rx;

   
   double hz = (double)rte_get_tsc_hz();
   printf("\nDPDK TSC Hz: %.2f\n", hz);
   printf("\n=== Average Cycles per Packet (total: %lu packets) ===\n", n_all_rx);
   printf("Average τ verification:  %.2f cycles  (%.2f µs)\n", avg_verify_tau, avg_verify_tau / hz * 1e6);
   printf("Average π verification:  %.2f cycles  (%.2f µs)\n", avg_verify_pi, avg_verify_pi / hz * 1e6);
   printf("Average C commitment:   %.2f cycles  (%.2f µs)\n", avg_com_c, avg_com_c / hz * 1e6);
   printf("Average π signing:       %.2f cycles  (%.2f µs)\n", avg_sign_pi, avg_sign_pi / hz * 1e6);
   printf("Average V confirmation:  %.2f cycles  (%.2f µs)\n", avg_conf_v, avg_conf_v / hz * 1e6);
   printf("Average τ signing:       %.2f cycles  (%.2f µs)\n", avg_sign_tau, avg_sign_tau / hz * 1e6);
   printf("Average MAC generation:  %.2f cycles  (%.2f µs)\n", avg_datatrans_gen_acseg, avg_datatrans_gen_acseg / hz * 1e6);
   printf("Average MAC verification:  %.2f cycles  (%.2f µs)\n", avg_datatrans_verify_acseg, avg_datatrans_verify_acseg / hz * 1e6);
   printf("Average Relay process:  %.2f cycles  (%.2f µs)\n", avg_router, avg_router / hz * 1e6);
   slave_finish_signal[lcore_id] = true;
   rte_free(nodes);
   // printf("lcore %d exiting...\n", lcore_id);
   return 0;
}



int main(int argc, char *argv[])
{
   // init_groupsig_once();
   uint8_t i = 0;
   // interpret cmdline config
   char *qargv = NULL, *opargv = NULL;

   int args_cnt = 0;
   for (i = 0; i < argc; i++)
   {
      // if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      //   if (strcmp(argv[i + 1], "server") == 0) role = ROLE_SERVER;
      //   else role = ROLE_CLIENT;
      // }
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
   //  size_t wanted_data_room = FRAME_SIZE + RTE_PKTMBUF_HEADROOM + 36;//1152B以上のパケット用 1664
   struct rte_mempool *pkt_pool0, *pkt_pool1;
   pkt_pool0 = rte_pktmbuf_pool_create("PKT_POOL0", // mempool name
                                       NUM_MBUFS,   // number_of_elements *2^q -1 is optimal
                                       256,         // cache_size
                                       0,           // prive_data
                                       RTE_MBUF_DEFAULT_BUF_SIZE,//1152//wanted_data_room,
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

    //    struct rte_eth_dev_info dev_info;
    //     rte_eth_dev_info_get(0, &dev_info);
      //   printf("Port 0: max_rx_queues=%u, max_tx_queues=%u\n",dev_info.max_rx_queues, dev_info.max_tx_queues);


   // Set source IPv4 address for RSS hash's input.
   for (i = 0; i < MAX_PORT; i++)
   {
      if (port_conf[i].nb_rxqs != 0)
      {
         init_rss_ipv4src(i);
         // set_rss_reta(i, port_conf[i].nb_rxqs);
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
      usleep(100000);
   }
   printf("Main: Setting exit signal...\n");
   slave_exit_signal = true;

   //    // ★★★ 追加: ワーカースレッドの完全終了を待つ ★★★
   // printf("Main: Waiting for all workers to exit completely...\n");
   // RTE_LCORE_FOREACH_WORKER(lcore_id) {
   //    if (lcore_conf[lcore_id].en == 1) {
   //       rte_eal_wait_lcore(lcore_id);
   //       printf("Main: Worker %d exited\n", lcore_id);
   //    }
   // }
   //}

// ========== グループ署名リソースの解放 ==========
// if (groupsig_initialized) {
//    printf("Main: Cleaning up group signature resources...\n");
//    if (shared_grpkey) {
//       groupsig_grp_key_free(shared_grpkey);
//       shared_grpkey = NULL;
//    }
//    if (shared_mgrkey) {
//       groupsig_mgr_key_free(shared_mgrkey);
//       shared_mgrkey = NULL;
//    }
//    if (shared_memkey) {
//       groupsig_mem_key_free(shared_memkey);
//       shared_memkey = NULL;
//    }
//    if (shared_gml) {
//       gml_free(shared_gml);
//       shared_gml = NULL;
//    }
//    if (shared_crl) {
//       crl_free(shared_crl);
//       shared_crl = NULL;
//    }
//    printf("Main: Group signature cleanup complete\n");
// }

   for (i = 0; i < MAX_PORT; i++)
   {

      if (port_conf[i].nb_rxqs != 0)
      {
         struct rte_eth_stats eth_stats;
         rte_eth_stats_get(i, &eth_stats);

         double iratio = (double)eth_stats.ipackets / (eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors);
         printf("Port %d: ipkts %zd, imiss %zd, ierr %zd (%lf), rx_nombuf %ld\n", i, eth_stats.ipackets, eth_stats.imissed, eth_stats.ierrors, iratio, eth_stats.rx_nombuf);

      }
   }

   sleep(1);
}