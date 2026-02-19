#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <utility>

#include "dpdk-util/eth_config2.h"

#define RECORD_SIZE (1000 * 1000)

extern size_t FRAME_SIZE;
extern double TX_INTERVAL;
extern char *filename_base;

extern uint8_t switch_port_list[MAX_SWITCH_PORT];
extern struct lcore_params lcore_conf[MAX_CORE_NUM];
extern struct port_params port_conf[MAX_PORT];

extern char *app_args[256][2];


extern bool slave_exit_signal;
extern int global_sync_nb_thread;
extern bool slave_finish_signal[MAX_CORE_NUM];

static void signal_handler(int signum);
static void print_option_config(void);
static void print_port_config(uint8_t port_id);
void print_lcore_status(uint8_t rxport, uint8_t rxq, uint8_t txport, uint8_t txq);
void write_record(char *filename_base, std::pair<uint64_t, uint64_t> *record, size_t record_size, uint32_t lcore_id);
static int run_forwarder(__rte_unused void *arg);
int main(int argc, char *argv[]);

#endif
