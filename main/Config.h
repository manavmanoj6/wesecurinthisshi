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

#define LORA_NSS 5
#define LORA_DIO0 2
#define LORA_RST 27
#define LORA_DIO1 4
#define LORA_SCK 18
#define LORA_MISO 19
#define LORA_MOSI 23

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