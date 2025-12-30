#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"
#include "driver/uart.h"

#define TAG_CRYPTO "CRYPTO"
#define TAG_RADIO  "RADIO"
#define TAG_APP    "APP"
#define TAG_CONF   "CONFIG"

// ----------------------------------------------------------------------------
// PIN CONFIGURATION
// Uncomment the board you are currently flashing:
// ----------------------------------------------------------------------------

#define BOARD_CROWPANEL   // <--- Uncomment this for the Display Board
//#define BOARD_STANDARD    // <--- Uncomment this for the Regular ESP32

// ----------------------------------------------------------------------------
#ifdef BOARD_CROWPANEL
    // MAPPING FOR CROWPANEL 2.4" (Expansion Ports)
    #define LORA_SCK    22
    #define LORA_MOSI   21
    #define LORA_MISO   16
    #define LORA_NSS    17
    #define LORA_RST    32  
    #define LORA_DIO0   25
    #define LORA_DIO1   RADIOLIB_NC 
#endif

#ifdef BOARD_STANDARD
    // MAPPING FOR STANDARD ESP32 (Best Performance / VSPI)
    #define LORA_SCK    18
    #define LORA_MOSI   23
    #define LORA_MISO   19
    #define LORA_NSS    5
    #define LORA_RST    14
    #define LORA_DIO0   26
    #define LORA_DIO1   RADIOLIB_NC 
#endif

#define TYPE_CHAT 0x01
#define TYPE_HANDSHAKE 0x02
#define TYPE_HANDSHAKE_ACK 0x03

#define BROADCAST_ID 255
#define MAX_PEERS 10

extern "C" {
    #include "ascon.h"
    #include "crypto_aead.h"
    #include "mlkem_api.h"
    #include "mldsa_api.h"
    #include "randombytes.h"
}

typedef struct __attribute__((packed)) {
    uint8_t to_id; uint8_t from_id; uint8_t type; uint8_t chunk_id; uint8_t total_chunks; uint16_t data_len; uint8_t payload[200];
} LoRaFrame_t;

typedef struct __attribute__((packed)) {
    uint16_t seq_num; uint16_t ct_len; uint8_t nonce[16]; uint8_t auth_tag[16]; uint8_t ciphertext[160];
} EncryptedChat_t;

#endif