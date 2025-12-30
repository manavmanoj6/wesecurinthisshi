#ifndef SHARED_H
#define SHARED_H

#include "Config.h"
#include "Hal.h"
#include "Peers.h"

// Hardware Objects
extern EspHal* hal;
extern SX1276* radio;
extern QueueHandle_t tx_queue;
extern PeerManager peerMgr;

// State Variables
extern uint8_t my_node_id;
extern uint8_t current_target;
extern uint8_t hardcoded_key[32];

// Buffers
extern uint8_t reassembly_buffer[5000];
extern uint32_t chunks_received_mask;
extern int64_t last_chunk_time;

// Crypto Keys
extern uint8_t my_sign_pk[];
extern uint8_t my_sign_sk[];

#endif