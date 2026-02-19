// // #ifndef ETH_CONFIG2_H

// // #include <rte_mempool.h>
// // #include <rte_ethdev.h>
// // #include <rte_ether.h>
// // #include <stdio.h>
// // #include <stdint.h>

// // #define MAX_SWITCH_PORT 128
// // #define RX_RING_SIZE 128
// // #define TX_RING_SIZE 512
// // #define NUM_MBUFS 2097151
// // #define BURST_SIZE 32
// // #define MAX_PORT 2
// // #define MAX_CORE_NUM 80

// // #define MAC_CLIENT_PORT0 "3c:fd:fe:16:60:28"
// // #define MAC_CLIENT_PORT1 "3c:fd:fe:16:60:2a"
// // #define MAC_CLIENT_PORT2 "3c:fd:fe:16:5c:48"
// // #define MAC_CLIENT_PORT3 "3c:fd:fe:16:5c:4a"

// // #define MAC_ROUTER_PORT0 "3c:fd:fe:16:5c:48"
// // #define MAC_ROUTER_PORT1 "3c:fd:fe:16:5c:4a"
// // #define MAC_ROUTER_PORT2 "3c:fd:fe:16:60:28"
// // #define MAC_ROUTER_PORT3 "3c:fd:fe:16:60:2a"

// // #define PRINT_MAC(addr) printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8                       \
// //                                ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,                     \
// //                                addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], \
// //                                addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])

// // struct port_params
// // {
// //    uint8_t nb_rxqs;
// //    uint8_t nb_txqs;
// // } __rte_cache_aligned;

// // struct lcore_params
// // {
// //    uint8_t en;
// //    uint8_t rxport;
// //    uint8_t rxqueue;
// //    uint8_t txport;
// //    uint8_t txqueue;
// // } __rte_cache_aligned;

// // static uint8_t i40e_mykey[52] = {
// // 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
// // 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
// // 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
// // 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
// // 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
// // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// // 0x00, 0x00, 0x00, 0x00
// // };

// // static const struct rte_eth_conf port_conf_default = {
// //   .rxmode = { 
// //     .mq_mode = ETH_MQ_RX_RSS, 
// //     .max_rx_pkt_len = RTE_ETHER_MAX_LEN}, 
// //     .rx_adv_conf = {
// //         .rss_conf = {
// //             // .rss_key = i40e_mykey, 
// //             // .rss_key_len = 52, 
// //             .rss_hf = ETH_RSS_NONFRAG_IPV4_OTHER
// //         }
// //     }  
// // };

// // // static const struct rte_eth_conf port_conf_default = {
// // //     .rxmode = {
// // //         .mq_mode = ETH_MQ_RX_NONE,
// // //         .max_rx_pkt_len = RTE_ETHER_MAX_LEN},};

// // void port_init(uint8_t port, struct rte_mempool *pkt_pool, struct port_params *p_conf);
// // void create_eth_hdr(struct rte_ether_hdr *eth_hdr);
// // void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf);
// // void init_rss_ipv4src(uint8_t port_id);

// // #define ETH_CONFIG2_H
// // #endif
// #ifndef ETH_CONFIG2_H
// #define ETH_CONFIG2_H

// #include <rte_mempool.h>
// #include <rte_ethdev.h>
// #include <rte_ether.h>
// #include <stdio.h>
// #include <stdint.h>
// #include <inttypes.h> // PRIx8

// /* ---------------------------
//    互換マクロ: 古い名前 -> 新しい RTE_* 名前空間
//    --------------------------- */
// #ifndef RTE_ETH_MQ_RX_RSS
//   /* 古い ETH_MQ_RX_RSS を使っているコード向け */
//   #ifdef ETH_MQ_RX_RSS
//     #define RTE_ETH_MQ_RX_RSS ETH_MQ_RX_RSS
//   #endif
// #endif

// #ifndef RTE_ETH_RSS_NONFRAG_IPV4_OTHER
//   #ifdef ETH_RSS_NONFRAG_IPV4_OTHER
//     #define RTE_ETH_RSS_NONFRAG_IPV4_OTHER ETH_RSS_NONFRAG_IPV4_OTHER
//   #endif
// #endif

// /* map possible older names to new ones used in modern DPDK */
// #ifndef RTE_ETH_RX_OFFLOAD_JUMBO_FRAME
//   #ifdef DEV_RX_OFFLOAD_JUMBO_FRAME
//     #define RTE_ETH_RX_OFFLOAD_JUMBO_FRAME DEV_RX_OFFLOAD_JUMBO_FRAME
//   #endif
// #endif

// #ifndef RTE_ETH_TX_OFFLOAD_MULTI_SEGS
//   #ifdef DEV_TX_OFFLOAD_MULTI_SEGS
//     #define RTE_ETH_TX_OFFLOAD_MULTI_SEGS DEV_TX_OFFLOAD_MULTI_SEGS
//   #endif
// #endif

// #ifndef RTE_ETH_LINK_DOWN
//   #ifdef ETH_LINK_DOWN
//     #define RTE_ETH_LINK_DOWN ETH_LINK_DOWN
//   #endif
// #endif

// #ifndef RTE_LCORE_FOREACH_WORKER
//   #ifdef RTE_LCORE_FOREACH_SLAVE
//     #define RTE_LCORE_FOREACH_WORKER RTE_LCORE_FOREACH_SLAVE
//   #endif
// #endif

// /* ---------------------------
//    定数と構造体
//    --------------------------- */
// #define MAX_SWITCH_PORT 128
// #define RX_RING_SIZE 128
// #define TX_RING_SIZE 512
// #define NUM_MBUFS 2097151
// #define BURST_SIZE 64
// #define MAX_PORT 2
// #define MAX_CORE_NUM 80

// #define MAC_CLIENT_PORT0 "3c:fd:fe:16:60:28"
// #define MAC_CLIENT_PORT1 "3c:fd:fe:16:60:2a"
// #define MAC_CLIENT_PORT2 "3c:fd:fe:16:5c:48"
// #define MAC_CLIENT_PORT3 "3c:fd:fe:16:5c:4a"

// #define MAC_ROUTER_PORT0 "3c:fd:fe:16:5c:48"
// #define MAC_ROUTER_PORT1 "3c:fd:fe:16:5c:4a"
// #define MAC_ROUTER_PORT2 "3c:fd:fe:16:60:28"
// #define MAC_ROUTER_PORT3 "3c:fd:fe:16:60:2a"

// #define PRINT_MAC(addr) printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8                       \
//                                ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,                     \
//                                addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], \
//                                addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])

// struct port_params
// {
//    uint8_t nb_rxqs;
//    uint8_t nb_txqs;
// } __rte_cache_aligned;

// struct lcore_params
// {
//    uint8_t en;
//    uint8_t rxport;
//    uint8_t rxqueue;
//    uint8_t txport;
//    uint8_t txqueue;
// } __rte_cache_aligned;

// /* example RSS key (kept as in your original) */
// static uint8_t i40e_mykey[52] = {
//   0x6d,0x5a,0x56,0xda,0x25,0x5b,0x0e,0xc2,
//   0x41,0x67,0x25,0x3d,0x43,0xa3,0x8f,0xb0,
//   0xd0,0xca,0x2b,0xcb,0xae,0x7b,0x30,0xb4,
//   0x77,0xcb,0x2d,0xa3,0x80,0x30,0xf2,0x0c,
//   0x6a,0x42,0xb7,0x3b,0xbe,0xac,0x01,0xfa,
//   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
//   0x00,0x00,0x00,0x00
// };

// /* port_conf_default: RTE_* 名称を使う（互換マクロが定義されていればそちらを使用） */
// static const struct rte_eth_conf port_conf_default = {
//   .rxmode = {
//     // .mq_mode = RTE_ETH_MQ_RX_RSS,
//     .mq_mode = RTE_ETH_MQ_RX_NONE,  // RSS無効
//     .offloads = 0,  
//     /* note: some DPDK versions do not include max_rx_pkt_len in rxmode
//        so we avoid assigning it here; use rte_eth_dev_set_mtu() at runtime if needed */
//   },
// //   .rx_adv_conf = {
// //     .rss_conf = {
// //       /* .rss_key and .rss_key_len can be set if needed */
// //       .rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_OTHER
// //     }
// //   }
//   .txmode = {
//         .offloads = 0,
//     },
// };

// void port_init(uint8_t port, struct rte_mempool *pkt_pool, struct port_params *p_conf);
// void create_eth_hdr(struct rte_ether_hdr *eth_hdr);
// void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf);
// void init_rss_ipv4src(uint8_t port_id);

// #endif /* ETH_CONFIG2_H */

#ifndef ETH_CONFIG2_H

#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_SWITCH_PORT 128
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512
#define NUM_MBUFS 2097151
#define BURST_SIZE 32
#define MAX_PORT 2
#define MAX_CORE_NUM 80

#define MAC_CLIENT_PORT0 "3c:fd:fe:16:60:28"
#define MAC_CLIENT_PORT1 "3c:fd:fe:16:60:2a"
#define MAC_CLIENT_PORT2 "3c:fd:fe:16:5c:48"
#define MAC_CLIENT_PORT3 "3c:fd:fe:16:5c:4a"

#define MAC_ROUTER_PORT0 "3c:fd:fe:16:5c:48"
#define MAC_ROUTER_PORT1 "3c:fd:fe:16:5c:4a"
#define MAC_ROUTER_PORT2 "3c:fd:fe:16:60:28"
#define MAC_ROUTER_PORT3 "3c:fd:fe:16:60:2a"

#define PRINT_MAC(addr) printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8                       \
                               ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,                     \
                               addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], \
                               addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])

struct port_params
{
   uint8_t nb_rxqs;
   uint8_t nb_txqs;
} __rte_cache_aligned;

struct lcore_params
{
   uint8_t en;
   uint8_t rxport;
   uint8_t rxqueue;
   uint8_t txport;
   uint8_t txqueue;
} __rte_cache_aligned;

static uint8_t i40e_mykey[52] = {
0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00
};

static const struct rte_eth_conf port_conf_default = {
  .rxmode = { 
    .mq_mode = ETH_MQ_RX_RSS, 
    .max_rx_pkt_len = 9000,//RTE_ETHER_MAX_LEN}, //
    .offloads = DEV_RX_OFFLOAD_JUMBO_FRAME,},//
    .rx_adv_conf = {
        .rss_conf = {
            // .rss_key = i40e_mykey, 
            // .rss_key_len = 52, 
            .rss_key = NULL,
            .rss_hf = ETH_RSS_NONFRAG_IPV4_OTHER
        }
    }, 
    // .txmode = {
    //     .mq_mode = ETH_MQ_TX_NONE,
    // },
};

// static const struct rte_eth_conf port_conf_default = {
//     .rxmode = {
//         .mq_mode = ETH_MQ_RX_NONE,
//         .max_rx_pkt_len = RTE_ETHER_MAX_LEN},};

void port_init(uint8_t port, struct rte_mempool *pkt_pool, struct port_params *p_conf);
void create_eth_hdr(struct rte_ether_hdr *eth_hdr);
void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf);
void init_rss_ipv4src(uint8_t port_id);

#define ETH_CONFIG2_H
#endif
