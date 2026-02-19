// // #include <stdio.h>

// // #include <rte_ethdev.h>
// // #include <rte_mempool.h>
// // #include <rte_ether.h>

// // #include "eth_config2.h"

// // void port_init(uint8_t port, struct rte_mempool *pkt_pool, struct port_params *p_conf)
// // {



// //    // ジャンボフレーム対応の設定を追加
// //    struct rte_eth_conf port_conf_jumbo = port_conf_default;
// //    port_conf_jumbo.rxmode.max_rx_pkt_len = 9000;  // 修正: mtu → max_rx_pkt_len
// //    port_conf_jumbo.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;  // 修正: RTE_ETH → DEV
// //    port_conf_jumbo.txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;   // 修正: RTE_ETH → DEV

// //    int ret;
// //    ret = rte_eth_dev_configure(port,                 // port ID
// //                                p_conf[port].nb_rxqs, // number of rx_queues
// //                                p_conf[port].nb_txqs, // number of tx_queues
// //                                &port_conf_jumbo);

// //    if (ret < 0)
// //       printf("Cannot configure device: err=%d, port=%u\n", ret, port);

// //    uint8_t qid;

// //    for (qid = 0; qid < p_conf[port].nb_rxqs; qid++)
// //    {

// //       ret = rte_eth_rx_queue_setup(port,
// //                                    qid,
// //                                    RX_RING_SIZE,
// //                                    rte_eth_dev_socket_id(port),
// //                                    NULL,
// //                                    pkt_pool);
// //       if (ret < 0)
// //       {
// //          printf("Rx Queue not set up\n");
// //          exit(1);
// //       }
// //    }

// //    for (qid = 0; qid < p_conf[port].nb_txqs; qid++)
// //    {
// //       ret = rte_eth_tx_queue_setup(port, // port ID
// //                                    qid,  // tx_queue_id
// //                                    TX_RING_SIZE,
// //                                    rte_eth_dev_socket_id(port), // socket_id
// //                                    NULL);
// //       if (ret < 0)
// //       {
// //          printf("Tx Queue not set up\n");
// //          exit(1);
// //       }
// //    }

// //    ret = rte_eth_dev_start(port);
// //    if (ret < 0)
// //       rte_exit(0, "Port could not be initialized");

// //    ret = rte_eth_promiscuous_enable(port);
// //    if (ret < 0)
// //       rte_exit(0, "Port could not be initialized at promiscuous");

// //    struct rte_eth_fc_conf fc_conf;
// //    rte_eth_dev_flow_ctrl_get(port, &fc_conf);
// //    fc_conf.autoneg = 0;
// //    rte_eth_dev_flow_ctrl_set(port, &fc_conf);

// // }

// // // create ether header
// // void create_eth_hdr(struct rte_ether_hdr *eth_hdr)
// // {
// //    int values[6];
// //    int i, j;
// //    for (i = 0; i < 4; i++)
// //    {
// //       rte_eth_macaddr_get(i, &eth_hdr[i].s_addr);
// //       if (i == 0)
// //       {
// //          sscanf(MAC_CLIENT_PORT0, "%x:%x:%x:%x:%x:%x",
// //                 &values[0], &values[1], &values[2],
// //                 &values[3], &values[4], &values[5]);
// //       }
// //       else if (i == 1)
// //       {
// //          sscanf(MAC_CLIENT_PORT1, "%x:%x:%x:%x:%x:%x",
// //                 &values[0], &values[1], &values[2],
// //                 &values[3], &values[4], &values[5]);
// //       }
// //       else if (i == 2)
// //       {
// //          sscanf(MAC_CLIENT_PORT2, "%x:%x:%x:%x:%x:%x",
// //                 &values[0], &values[1], &values[2],
// //                 &values[3], &values[4], &values[5]);
// //       }
// //       else if (i == 3)
// //       {
// //          sscanf(MAC_CLIENT_PORT3, "%x:%x:%x:%x:%x:%x",
// //                 &values[0], &values[1], &values[2],
// //                 &values[3], &values[4], &values[5]);
// //       }
// //       for (j = 0; j < 6; ++j)
// //          eth_hdr[i].d_addr.addr_bytes[j] = (uint8_t)values[j];
// //       eth_hdr[i].ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4); // ghost type
// //    }
// // }

// // // parse argv and initialize port---queue---core mapping
// // void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf)
// // {
// //    // 初期化
// //     for (int i = 0; i < 44; i++) {
// //         lc_conf[i].en = 0;
// //     }

// //     char *token = strtok(qargv, "(), ");
// //     while (token != NULL) {
// //         int core = atoi(token);

// //         token = strtok(NULL, "(), ");
// //         if (token == NULL) break;
// //         int rxport = atoi(token);

// //         token = strtok(NULL, "(), ");
// //         if (token == NULL) break;
// //         int rxq = atoi(token);

// //         // lcore設定
// //         lc_conf[core].en = 1;
// //         lc_conf[core].rxport = rxport;
// //         lc_conf[core].txport = rxport;
// //         lc_conf[core].rxqueue = rxq;
// //         lc_conf[core].txqueue = rxq;

// //         // port設定
// //         p_conf[rxport].nb_rxqs++;
// //         p_conf[rxport].nb_txqs++;

// //         printf("Config: lcore=%d port=%d queue=%d\n", core, rxport, rxq);

// //         // 次のトークンへ
// //         token = strtok(NULL, "(), ");
// //     }
// //    // // port init
// //    // uint64_t i = 0;
// //    // uint64_t j = 0;

// //    // for (i = 0; i < 44; i++)
// //    // {
// //    //    lc_conf[i].en = 0;
// //    // }

// //    // char *map[44];
// //    // for (size_t x = 0; x < 44; x++)
// //    //    map[x] = NULL;

// //    // size_t nb_lcore = 0;
// //    // char *p = strtok(qargv, " ");
// //    // while (p != NULL)
// //    // {
// //    //    map[nb_lcore] = p;
// //    //    nb_lcore++;
// //    //    p = strtok(NULL, " ");
// //    // }


// //    // int n_lcores = 0;
// //    // for (size_t x = 0; x < 44; x++)
// //    // {
// //    //    if (map[x] != NULL)
// //    //    {
// //    //       map[x] = strtok(map[x], "(");
// //    //       map[x] = strtok(map[x], ")");

// //    //       int core, rxport, rxq, txq;
// //    //       char *pp = strtok(map[x], ",");
// //    //       if (pp == NULL)
// //    //       {
// //    //          printf("Error: <MAPPING> format is not valid\n");
// //    //          exit(1);
// //    //       }
// //    //       core = atoi(pp);
// //    //       lc_conf[core].en = 1;
// //    //       n_lcores++;

// //    //       pp = strtok(NULL, ",");
// //    //       if (pp == NULL)
// //    //       {
// //    //          printf("Error: <MAPPING> format is not valid\n");
// //    //          exit(1);
// //    //       }
// //    //       rxport = atoi(pp);
// //    //       lc_conf[core].rxport = rxport;
// //    //       lc_conf[core].txport = rxport;

// //    //       pp = strtok(NULL, ",");
// //    //       if (pp == NULL)
// //    //       {
// //    //          printf("Error: <MAPPING> format is not valid\n");
// //    //          exit(1);
// //    //       }
// //    //       rxq = atoi(pp);
// //    //       lc_conf[core].rxqueue = rxq;
// //    //       lc_conf[core].txqueue = rxq;
// //    //    }
// //    // }

// //    // for (i = 0; i < 44; i++)
// //    // {
// //    //    if (lc_conf[i].en == 1)
// //    //    {
// //    //       p_conf[lc_conf[i].rxport].nb_rxqs++;
// //    //       p_conf[lc_conf[i].txport].nb_txqs++;
// //    //    }
// //    // }
// // }

// // void init_rss_ipv4src(uint8_t port_id)
// // {
// //    struct rte_eth_hash_filter_info info;
// //    memset(&info, 0, sizeof(info));
// //    info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
// //    info.info.input_set_conf.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
// //    info.info.input_set_conf.field[0] = RTE_ETH_INPUT_SET_L3_SRC_IP4;
// //    info.info.input_set_conf.inset_size = 1;
// //    info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
// //    rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
// //    return;
// // }

// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>

// #include <rte_ethdev.h>
// #include <rte_mempool.h>
// #include <rte_ether.h>

// #include "eth_config2.h"


// void port_init(uint8_t port, struct rte_mempool *pkt_pool, struct port_params *p_conf)
// {
//    // ジャンボフレーム有効化（DPDK 25.11 では offloads フラグは廃止済）
//    uint32_t mtu_size = 9000;
//    uint32_t max_rx_pkt_len = mtu_size + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
//    //  int ret;
//    //  struct rte_eth_dev_info dev_info;
//    //  struct rte_eth_conf port_conf = {0};

//    //  // デバイス情報取得
//    //  rte_eth_dev_info_get(port, &dev_info);

//    //  // RX/TX 設定
//    //  port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
//    //  port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;


//    //  // ポート設定
//    //  ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
//    //  if (ret < 0) {
//    //      printf("Cannot configure device: err=%d\n", ret);
//    //      return;
//    //  }

//    //  // RX queue設定
//    //  struct rte_eth_rxconf rx_conf = dev_info.default_rxconf;
//    //  rx_conf.offloads = dev_info.rx_offload_capa;
//    //  ret = rte_eth_rx_queue_setup(port, 0, 1024, rte_eth_dev_socket_id(port), &rx_conf, pkt_pool);
//    //  if (ret < 0) {
//    //      printf("Cannot setup RX queue: err=%d\n", ret);
//    //      return;
//    //  }

//    //  // TX queue設定
//    //  struct rte_eth_txconf tx_conf = dev_info.default_txconf;
//    //  tx_conf.offloads = dev_info.tx_offload_capa;
//    //  ret = rte_eth_tx_queue_setup(port, 0, 1024, rte_eth_dev_socket_id(port), &tx_conf);
//    //  if (ret < 0) {
//    //      printf("Cannot setup TX queue: err=%d\n", ret);
//    //      return;
//    //  }

//    //  // ポート開始
//    //  ret = rte_eth_dev_start(port);
//    //  if (ret < 0) {
//    //      printf("Cannot start device: err=%d\n", ret);
//    //      return;
//    //  }
//    //  printf("\n\n\n\n\n\nPort %u started successfully.\n\n\n\n\n\n", port);

//    struct rte_eth_conf port_conf_jumbo = port_conf_default;
//    struct rte_eth_dev_info dev_info;
//    int ret;
//    port_conf_jumbo.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
//    port_conf_jumbo.rxmode.offloads = 0;
//    port_conf_jumbo.txmode.offloads = 0;

//    /* デバイス情報を先に取得してログ */
//    memset(&dev_info, 0, sizeof(dev_info));
//    int ret_info = rte_eth_dev_info_get(port, &dev_info);
//    char dev_name[RTE_ETH_NAME_MAX_LEN];
//    rte_eth_dev_get_name_by_port(port, dev_name);


//    // RSSハッシュタイプを設定
//    // port_conf_jumbo.rx_adv_conf.rss_conf.rss_key = NULL; // デフォルトキー使用
//    // port_conf_jumbo.rx_adv_conf.rss_conf.rss_key_len = 0;
//    port_conf_jumbo.rx_adv_conf.rss_conf.rss_key = i40e_mykey; 
//    port_conf_jumbo.rx_adv_conf.rss_conf.rss_key_len = sizeof(i40e_mykey);
//    port_conf_jumbo.rx_adv_conf.rss_conf.rss_hf = 
//        (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP) & dev_info.flow_type_rss_offloads;
   
//    printf("Port %u: Configuring RSS with hash types: 0x%lx\n", 
//           port, port_conf_jumbo.rx_adv_conf.rss_conf.rss_hf);


//    /* configure */
//    ret = rte_eth_dev_configure(port, p_conf[port].nb_rxqs, p_conf[port].nb_txqs, &port_conf_jumbo);
//    if (ret < 0) {
//        printf("ERROR: rte_eth_dev_configure(port=%u) failed: ret=%d errno=%d (%s)\n",
//               port, ret, rte_errno, rte_strerror(rte_errno));
//        rte_exit(EXIT_FAILURE, "Cannot configure device (port %u)\n", port);
//    } else {
//        printf("rte_eth_dev_configure ok for port %u (rxq=%u txq=%u)\n",
//               port, p_conf[port].nb_rxqs, p_conf[port].nb_txqs);
//    }

//    /* rx queue setup - log each ret */
//    for (uint8_t qid = 0; qid < p_conf[port].nb_rxqs; qid++) {
//       ret = rte_eth_rx_queue_setup(port, qid, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, pkt_pool);
//       if (ret < 0) {
//          printf("ERROR: rte_eth_rx_queue_setup(port=%u q=%u) failed: ret=%d errno=%d (%s)\n",
//                 port, qid, ret, rte_errno, rte_strerror(rte_errno));
//          rte_exit(EXIT_FAILURE, "Rx Queue not set up (port %u q %u)\n", port, qid);
//       }
//    }

//    /* tx queue setup - log each ret */
//    for (uint8_t qid = 0; qid < p_conf[port].nb_txqs; qid++) {
//       ret = rte_eth_tx_queue_setup(port, qid, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
//       if (ret < 0) {
//          printf("ERROR: rte_eth_tx_queue_setup(port=%u q=%u) failed: ret=%d errno=%d (%s)\n",
//                 port, qid, ret, rte_errno, rte_strerror(rte_errno));
//          rte_exit(EXIT_FAILURE, "Tx Queue not set up (port %u q %u)\n", port, qid);
//       }
//    }
   
//    // MTU設定
//    ret = rte_eth_dev_set_mtu(port, mtu_size);
//    if (ret < 0)
//        printf("Warning: failed to set MTU=%u on port %u (ret=%d)\n", mtu_size, port, ret);
   
//    /* start device and check return */
//    ret = rte_eth_dev_start(port);
//    if (ret < 0) {
//       printf("ERROR: rte_eth_dev_start(port=%u) failed: ret=%d errno=%d (%s)\n",
//              port, ret, rte_errno, rte_strerror(rte_errno));
//       rte_exit(EXIT_FAILURE, "Port could not be initialized (port %u)\n", port);
//    }
//    printf("\nPort %u started successfully.\n\n", port);

//    // struct rte_ether_addr mac;
//    // rte_eth_macaddr_get(port, &mac);
//    // printf("DPDK Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//    //       port,
//    //       mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
//    //       mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);


//    //  // RXパケット長設定（関数は廃止、代わりに `rte_eth_dev_info` 経由で確認）
//    //  printf("Port %u info: max_rx_pktlen supported=%u, setting to %u\n",
//    //         port, dev_info.max_rx_pktlen, max_rx_pkt_len);

//    //  // リンクアップ待ち
//    //  struct rte_eth_link link;
//    //  rte_eth_link_get_nowait(port, &link);
//    //  if (link.link_status)
//    //      printf("Port %u Link Up - speed %u Mbps - %s\n",
//    //             port, link.link_speed,
//    //             (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex");
//    //  else
//    //      printf("Port %u Link Down\n", port);
//    // int reta_size = dev_info.reta_size;
//    // int n_groups = (reta_size + RTE_ETH_RETA_GROUP_SIZE - 1) / RTE_ETH_RETA_GROUP_SIZE;

//    // printf("DEBUG: dev_info.reta_size=%d, RTE_ETH_RETA_GROUP_SIZE=%d, n_groups=%d\n",
//    //       reta_size, RTE_ETH_RETA_GROUP_SIZE, n_groups);

//    // /* 1) 現在の RSS ハッシュ conf を取得して表示 */
//    // struct rte_eth_rss_conf rss_get;
//    // memset(&rss_get, 0, sizeof(rss_get));
//    // rss_get.rss_key = NULL;
//    // rss_get.rss_key_len = 0;
//    // int rc = rte_eth_dev_rss_hash_conf_get(port, &rss_get);
//    // if (rc == 0) {
//    //    printf("DEBUG: rss_hf = 0x%lx, rss_key_len = %u\n",
//    //          (unsigned long)rss_get.rss_hf, rss_get.rss_key_len);
//    // } else {
//    //    printf("DEBUG: rte_eth_dev_rss_hash_conf_get failed: %d\n", rc);
//    // }

//    // /* 2) RETA の現在値を読み出して表示 */
//    // struct rte_eth_rss_reta_entry64 *reta_query =
//    //    (struct rte_eth_rss_reta_entry64 *)calloc(n_groups, sizeof(*reta_query));
//    // if (!reta_query) {
//    //    printf("DEBUG: calloc reta_query failed\n");
//    // } else {
//    //    rc = rte_eth_dev_rss_reta_query(port, reta_query, n_groups);
//    //    if (rc != 0) {
//    //       printf("DEBUG: rte_eth_dev_rss_reta_query failed: %d\n", rc);
//    //    } else {
//    //       printf("DEBUG: RETA table (first %d entries):\n", reta_size);
//    //       for (int i = 0; i < reta_size; ++i) {
//    //             int g = i / RTE_ETH_RETA_GROUP_SIZE;
//    //             int idx = i % RTE_ETH_RETA_GROUP_SIZE;
//    //             printf("%d:", reta_query[g].reta[idx]);
//    //             if ((i % 32) == 31) printf("\n");
//    //       }
//    //       printf("\n");
//    //    }
//    //    free(reta_query);
//    // }

//    // /* 3) ポートの実際の nb_rxqs を表示 */
//    // struct rte_eth_dev_info dev_info2;
//    // rc = rte_eth_dev_info_get(port, &dev_info2);
//    // printf("DEBUG: dev_info.max_rx_queues=%u, configured nb_rxqs=%u\n",
//    //       dev_info2.max_rx_queues, p_conf[port].nb_rxqs);


//    // **************ここ変えたらいけた？**************
//    ret = rte_eth_promiscuous_enable(port);
//    if (ret < 0)
//       rte_exit(0, "Port could not be initialized at promiscuous");

//    struct rte_eth_fc_conf fc_conf;
//    rte_eth_dev_flow_ctrl_get(port, &fc_conf);
//    fc_conf.autoneg = 0;
//    rte_eth_dev_flow_ctrl_set(port, &fc_conf);
// }


// /* create_eth_hdr: new API では struct rte_ether_hdr に dst_addr/src_addr */
// void create_eth_hdr(struct rte_ether_hdr *eth_hdr)
// {
//    int values[6];
//    int i, j;
//    struct rte_ether_addr mac;

//    for (i = 0; i < 4; i++)
//    {
//       // /* rte_eth_macaddr_get は struct rte_ether_addr を受け取るので、それを ether_hdr の src_addr にコピー */
//       // rte_eth_macaddr_get(i, &mac);
//       // printf("Port MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//       //        mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
//       //        mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
//       // /* コピー先が src_addr というフィールド名である前提 */
//       // /* 一般的な構造:
//       //    struct rte_ether_hdr {
//       //        struct rte_ether_addr dst_addr;
//       //        struct rte_ether_addr src_addr;
//       //        rte_be16_t ether_type;
//       //    };
//       // */
//       // memcpy(&eth_hdr[i].src_addr, &mac, sizeof(struct rte_ether_addr));

//       // if (i == 0)
//       // {
//       //    sscanf(MAC_CLIENT_PORT0, "%x:%x:%x:%x:%x:%x",
//       //           &values[0], &values[1], &values[2],
//       //           &values[3], &values[4], &values[5]);
//       // }
//       // else if (i == 1)
//       // {
//       //    sscanf(MAC_CLIENT_PORT1, "%x:%x:%x:%x:%x:%x",
//       //           &values[0], &values[1], &values[2],
//       //           &values[3], &values[4], &values[5]);
//       // }
//       // else if (i == 2)
//       // {
//       //    sscanf(MAC_CLIENT_PORT2, "%x:%x:%x:%x:%x:%x",
//       //           &values[0], &values[1], &values[2],
//       //           &values[3], &values[4], &values[5]);
//       // }
//       // else if (i == 3)
//       // {
//       //    sscanf(MAC_CLIENT_PORT3, "%x:%x:%x:%x:%x:%x",
//       //           &values[0], &values[1], &values[2],
//       //           &values[3], &values[4], &values[5]);
//       // }
//       // for (j = 0; j < 6; ++j)
//       //    eth_hdr[i].dst_addr.addr_bytes[j] = (uint8_t)values[j];
//       // eth_hdr[i].ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4); /* ether type */
//       int values[6];
//       int i, j;
//       for (i = 0; i < 4; i++)
//       {
//          rte_eth_macaddr_get(i, &eth_hdr[i].dst_addr);
//          if (i == 0)
//          {
//             sscanf(MAC_CLIENT_PORT0, "%x:%x:%x:%x:%x:%x",
//                      &values[0], &values[1], &values[2],
//                      &values[3], &values[4], &values[5]);
//          }
//          else if (i == 1)
//          {
//             sscanf(MAC_CLIENT_PORT1, "%x:%x:%x:%x:%x:%x",
//                      &values[0], &values[1], &values[2],
//                      &values[3], &values[4], &values[5]);
//          }
//          else if (i == 2)
//          {
//             sscanf(MAC_CLIENT_PORT2, "%x:%x:%x:%x:%x:%x",
//                      &values[0], &values[1], &values[2],
//                      &values[3], &values[4], &values[5]);
//          }
//          else if (i == 3)
//          {
//             sscanf(MAC_CLIENT_PORT3, "%x:%x:%x:%x:%x:%x",
//                      &values[0], &values[1], &values[2],
//                      &values[3], &values[4], &values[5]);
//          }
//          for (j = 0; j < 6; ++j)
//             eth_hdr[i].dst_addr.addr_bytes[j] = (uint8_t)values[j];
//          eth_hdr[i].ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4); // ghost type
//       }
//       printf ("Port MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//              eth_hdr[i].src_addr.addr_bytes[0], eth_hdr[i].src_addr.addr_bytes[1],
//              eth_hdr[i].src_addr.addr_bytes[2], eth_hdr[i].src_addr.addr_bytes[3],
//              eth_hdr[i].src_addr.addr_bytes[4], eth_hdr[i].src_addr.addr_bytes[5]);
//    }
// }

// // /* parse_config: (そのまま) */
// // void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf)
// // {
// //    for (int i = 0; i < 44; i++) {
// //        lc_conf[i].en = 0;
// //    }

// //    char *token = strtok(qargv, "(), ");
// //    while (token != NULL) {
// //        int core = atoi(token);

// //        token = strtok(NULL, "(), ");
// //        if (token == NULL) break;
// //        int rxport = atoi(token);

// //        token = strtok(NULL, "(), ");
// //        if (token == NULL) break;
// //        int rxq = atoi(token);

// //        lc_conf[core].en = 1;
// //        lc_conf[core].rxport = rxport;
// //        lc_conf[core].txport = rxport;
// //        lc_conf[core].rxqueue = rxq;
// //        lc_conf[core].txqueue = rxq;

// //        p_conf[rxport].nb_rxqs++;
// //        p_conf[rxport].nb_txqs++;

// //        printf("Config: lcore=%d port=%d queue=%d\n", core, rxport, rxq);

// //        token = strtok(NULL, "(), ");
// //    }
// // }

// // parse argv and initialize port---queue---core mapping
// void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf)
// {
//    // // port init
//    // uint64_t i = 0;
//    // uint64_t j = 0;

//    // for (i = 0; i < 44; i++)
//    // {
//    //    lc_conf[i].en = 0;
//    // }

//    // char *map[44];
//    // for (size_t x = 0; x < 44; x++)
//    //    map[x] = NULL;

//    // size_t nb_lcore = 0;
//    // char *p = strtok(qargv, " ");
//    // while (p != NULL)
//    // {
//    //    map[nb_lcore] = p;
//    //    nb_lcore++;
//    //    p = strtok(NULL, " ");
//    // }


//    // int n_lcores = 0;
//    // for (size_t x = 0; x < 44; x++)
//    // {
//    //    if (map[x] != NULL)
//    //    {
//    //       map[x] = strtok(map[x], "(");
//    //       map[x] = strtok(map[x], ")");

//    //       int core, rxport, rxq, txq;
//    //       char *pp = strtok(map[x], ",");
//    //       if (pp == NULL)
//    //       {
//    //          printf("Error: <MAPPING> format is not valid\n");
//    //          exit(1);
//    //       }
//    //       core = atoi(pp);
//    //       lc_conf[core].en = 1;
//    //       n_lcores++;

//    //       pp = strtok(NULL, ",");
//    //       if (pp == NULL)
//    //       {
//    //          printf("Error: <MAPPING> format is not valid\n");
//    //          exit(1);
//    //       }
//    //       rxport = atoi(pp);
//    //       lc_conf[core].rxport = rxport;
//    //       lc_conf[core].txport = rxport;

//    //       pp = strtok(NULL, ",");
//    //       if (pp == NULL)
//    //       {
//    //          printf("Error: <MAPPING> format is not valid\n");
//    //          exit(1);
//    //       }
//    //       rxq = atoi(pp);
//    //       lc_conf[core].rxqueue = rxq;
//    //       lc_conf[core].txqueue = rxq;
//    //    }
//    // }

//    // for (i = 0; i < 44; i++)
//    // {
//    //    if (lc_conf[i].en == 1)
//    //    {
//    //       p_conf[lc_conf[i].rxport].nb_rxqs++;
//    //       p_conf[lc_conf[i].txport].nb_txqs++;
//    //    }
//    // }
//    // 初期化
//    for (int i = 0; i < 44; i++) {
//       lc_conf[i].en = 0;
//    }
//    for (int i = 0; i < MAX_PORT; i++) {
//       p_conf[i].nb_rxqs = 0;
//       p_conf[i].nb_txqs = 0;
//    }

//    // スペース区切りで各エントリを処理
//    char *token = strtok(qargv, " ");
//    while (token != NULL) {
//       // 括弧を削除
//       char *start = strchr(token, '(');
//       char *end = strchr(token, ')');
      
//       if (start && end) {
//          int core, port, queue;
//          if (sscanf(start, "(%d,%d,%d)", &core, &port, &queue) == 3) {
//             // printf("Parsed: core=%d port=%d queue=%d\n", core, port, queue);
            
//             lc_conf[core].en = 1;
//             lc_conf[core].rxport = port;
//             lc_conf[core].txport = port;
//             lc_conf[core].rxqueue = queue;
//             lc_conf[core].txqueue = queue;
            
//             p_conf[port].nb_rxqs++;
//             p_conf[port].nb_txqs++;
//          }
//       }
      
//       token = strtok(NULL, " ");
//    }
// }

// // /* init_rss_ipv4src: hash filter API が無ければスキップする */
// // void init_rss_ipv4src(uint8_t port_id)
// // {
// // #ifdef RTE_ETH_FILTER_HASH
// //    struct rte_eth_hash_filter_info info;
// //    memset(&info, 0, sizeof(info));
// // /* NOTE: some DPDK versions use RTE_ETH_HASH_FILTER_INPUT_SET_SELECT vs RTE_ETH_INPUT_SET_SELECT.
// //    Try to use the newer name if present, otherwise fallback. */
// // #ifdef RTE_ETH_HASH_FILTER_INPUT_SET_SELECT
// //    info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
// // #else
// //    info.info_type = RTE_ETH_INPUT_SET_SELECT; /* fallback if macro exists */
// // #endif

// //    info.info.input_set_conf.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
// //    info.info.input_set_conf.field[0] = RTE_ETH_INPUT_SET_L3_SRC_IP4;
// //    info.info.input_set_conf.inset_size = 1;
// //    info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;

// //    /* filter ctrl op: use RTE_ETH_FILTER_HASH and RTE_ETH_FILTER_SET if defined */
// // #if defined(RTE_ETH_FILTER_HASH) && defined(RTE_ETH_FILTER_SET)
// //    rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
// // #else
// //    /* If no filter control, print and skip */
// //    printf("Hash filter control API not available in this DPDK build\n");
// // #endif

// // #else
// //    /* no filter API: skip */
// //    printf("RSS hash filter APIs not supported on this DPDK build\n");
// // #endif

// //    return;
// // }

// //最新
// void init_rss_ipv4src(uint8_t port_id)
// {
//     printf("Setting up RSS for port %u...\n", port_id);
    
//     struct rte_eth_dev_info dev_info;
//     int ret = rte_eth_dev_info_get(port_id, &dev_info);
//     if (ret != 0) {
//         printf("Error getting device info for port %u: %d\n", port_id, ret);
//         return;
//     }
    
//     // RSS設定用の構造体
//     struct rte_eth_rss_conf rss_conf;
//     memset(&rss_conf, 0, sizeof(rss_conf));
    
//     // RSSハッシュタイプの設定（IPv4 TCP/UDP/その他）
//     rss_conf.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
    
//     // デバイスがサポートするRSSタイプに制限
//     rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    
//     if (rss_conf.rss_hf == 0) {
//         printf("Warning: No RSS types supported on port %u\n", port_id);
//         return;
//     }
    
//     // デフォルトのRSSキーを使用（NULLでデバイスのデフォルトを使用）
//     rss_conf.rss_key = NULL;
//     rss_conf.rss_key_len = 0;
    
//     // RSS設定を適用（ポート停止→設定→再起動が必要な場合がある）
//     printf("Port %u: Applying RSS config with hash types: 0x%lx\n", 
//            port_id, rss_conf.rss_hf);
    
//     ret = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
//     if (ret != 0) {
//         printf("Warning: RSS hash update failed for port %u: %d (%s)\n", 
//                port_id, ret, rte_strerror(-ret));
//         printf("Attempting to configure RSS during port setup instead...\n");
//     } else {
//         printf("Port %u: RSS hash update successful\n", port_id);
//     }
    
//    //  // RSS設定の確認
//    //  struct rte_eth_rss_conf rss_conf_get;
//    //  memset(&rss_conf_get, 0, sizeof(rss_conf_get));
//    //  rss_conf_get.rss_key = NULL;
//    //  rss_conf_get.rss_key_len = 0;
    
//    //  ret = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf_get);
//    //  if (ret == 0) {
//    //      printf("Port %u: Current RSS types: 0x%lx\n", port_id, rss_conf_get.rss_hf);
        
//    //      // 各RSSタイプの詳細を表示
//    //      if (rss_conf_get.rss_hf & RTE_ETH_RSS_IPV4)
//    //          printf("  - IPv4 enabled\n");
//    //      if (rss_conf_get.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_TCP)
//    //          printf("  - IPv4 TCP enabled\n");
//    //      if (rss_conf_get.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_UDP)
//    //          printf("  - IPv4 UDP enabled\n");
//    //      if (rss_conf_get.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_OTHER)
//    //          printf("  - IPv4 Other enabled\n");
//    //  } else {
//    //      printf("Warning: Could not get RSS config for port %u\n", port_id);
//    //  }
    
//     return;
// }



#include <stdio.h>

#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ether.h>

#include "eth_config2.h"

void port_init(uint8_t port, struct rte_mempool *pkt_pool, struct port_params *p_conf)
{
   int ret;
   ret = rte_eth_dev_configure(port,                 // port ID
                               p_conf[port].nb_rxqs, // number of rx_queues
                               p_conf[port].nb_txqs, // number of tx_queues
                               &port_conf_default);

   // --- DPDK 20.05 ジャンボフレーム設定 ---
   ////////////////////////
   struct rte_eth_conf local_conf = port_conf_default;

   ret = rte_eth_dev_configure(port, 
                               p_conf[port].nb_rxqs,
                               p_conf[port].nb_txqs,
                               &local_conf);

   if (ret < 0)
      printf("Cannot configure device: err=%d, port=%u\n", ret, port);

   // 修正点3: 明示的にMTUを設定する（L2ヘッダ分を除いたサイズ）
   // 8000バイトのフレームを扱う場合、MTUはそれ以上（例: 8500）に設定します
   ret = rte_eth_dev_set_mtu(port, 9000);
   if (ret < 0) {
       printf("Warning: Set MTU failed for port %u. Error: %d\n", port, ret);
   }
   ////////////////////////////////////////////

   if (ret < 0)
      printf("Cannot configure device: err=%d, port=%u\n", ret, port);

   uint8_t qid;

   for (qid = 0; qid < p_conf[port].nb_rxqs; qid++)
   {

      ret = rte_eth_rx_queue_setup(port,
                                   qid,
                                   RX_RING_SIZE,
                                   rte_eth_dev_socket_id(port),
                                   NULL,
                                   pkt_pool);
      if (ret < 0)
      {
         printf("Rx Queue not set up\n");
         exit(1);
      }
   }

   for (qid = 0; qid < p_conf[port].nb_txqs; qid++)
   {
      ret = rte_eth_tx_queue_setup(port, // port ID
                                   qid,  // tx_queue_id
                                   TX_RING_SIZE,
                                   rte_eth_dev_socket_id(port), // socket_id
                                   NULL);
      if (ret < 0)
      {
         printf("Tx Queue not set up\n");
         exit(1);
      }
   }

   ret = rte_eth_dev_start(port);
   if (ret < 0)
      rte_exit(0, "Port could not be initialized");

   ret = rte_eth_promiscuous_enable(port);
   if (ret < 0)
      rte_exit(0, "Port could not be initialized at promiscuous");

   struct rte_eth_fc_conf fc_conf;
   rte_eth_dev_flow_ctrl_get(port, &fc_conf);
   fc_conf.autoneg = 0;
   rte_eth_dev_flow_ctrl_set(port, &fc_conf);
}

// create ether header
void create_eth_hdr(struct rte_ether_hdr *eth_hdr)
{
   int values[6];
   int i, j;
   for (i = 0; i < 4; i++)
   {
      rte_eth_macaddr_get(i, &eth_hdr[i].s_addr);
      if (i == 0)
      {
         sscanf(MAC_CLIENT_PORT0, "%x:%x:%x:%x:%x:%x",
                &values[0], &values[1], &values[2],
                &values[3], &values[4], &values[5]);
      }
      else if (i == 1)
      {
         sscanf(MAC_CLIENT_PORT1, "%x:%x:%x:%x:%x:%x",
                &values[0], &values[1], &values[2],
                &values[3], &values[4], &values[5]);
      }
      else if (i == 2)
      {
         sscanf(MAC_CLIENT_PORT2, "%x:%x:%x:%x:%x:%x",
                &values[0], &values[1], &values[2],
                &values[3], &values[4], &values[5]);
      }
      else if (i == 3)
      {
         sscanf(MAC_CLIENT_PORT3, "%x:%x:%x:%x:%x:%x",
                &values[0], &values[1], &values[2],
                &values[3], &values[4], &values[5]);
      }
      for (j = 0; j < 6; ++j)
         eth_hdr[i].d_addr.addr_bytes[j] = (uint8_t)values[j];
      eth_hdr[i].ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4); // ghost type
   }
}

// parse argv and initialize port---queue---core mapping
void parse_config(char *qargv, struct port_params *p_conf, struct lcore_params *lc_conf)
{
   // port init
   uint64_t i = 0;
   uint64_t j = 0;

   for (i = 0; i < 44; i++)
   {
      lc_conf[i].en = 0;
   }

   char *map[44];
   for (size_t x = 0; x < 44; x++)
      map[x] = NULL;

   size_t nb_lcore = 0;
   char *p = strtok(qargv, " ");
   while (p != NULL)
   {
      map[nb_lcore] = p;
      nb_lcore++;
      p = strtok(NULL, " ");
   }


   int n_lcores = 0;
   for (size_t x = 0; x < 44; x++)
   {
      if (map[x] != NULL)
      {
         map[x] = strtok(map[x], "(");
         map[x] = strtok(map[x], ")");

         int core, rxport, rxq, txq;
         char *pp = strtok(map[x], ",");
         if (pp == NULL)
         {
            printf("Error: <MAPPING> format is not valid\n");
            exit(1);
         }
         core = atoi(pp);
         lc_conf[core].en = 1;
         n_lcores++;

         pp = strtok(NULL, ",");
         if (pp == NULL)
         {
            printf("Error: <MAPPING> format is not valid\n");
            exit(1);
         }
         rxport = atoi(pp);
         lc_conf[core].rxport = rxport;
         lc_conf[core].txport = rxport;

         pp = strtok(NULL, ",");
         if (pp == NULL)
         {
            printf("Error: <MAPPING> format is not valid\n");
            exit(1);
         }
         rxq = atoi(pp);
         lc_conf[core].rxqueue = rxq;
         lc_conf[core].txqueue = rxq;
      }
   }

   for (i = 0; i < 44; i++)
   {
      if (lc_conf[i].en == 1)
      {
         p_conf[lc_conf[i].rxport].nb_rxqs++;
         p_conf[lc_conf[i].txport].nb_txqs++;
      }
   }
}

void init_rss_ipv4src(uint8_t port_id)
{
   struct rte_eth_hash_filter_info info;
   memset(&info, 0, sizeof(info));
   info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
   info.info.input_set_conf.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
   info.info.input_set_conf.field[0] = RTE_ETH_INPUT_SET_L3_SRC_IP4;
   info.info.input_set_conf.inset_size = 1;
   info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
   rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
   return;
}