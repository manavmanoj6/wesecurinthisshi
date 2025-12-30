#include "Config.h"
#include "Hal.h"
#include "Peers.h"
#include "Shared.h" // Ensures type safety
#include "Tasks.h"

// --- DEFINITIONS OF SHARED VARIABLES ---
EspHal* hal = NULL;
SX1276* radio = NULL;
QueueHandle_t tx_queue = NULL;
PeerManager peerMgr;

uint8_t my_node_id = 1;
uint8_t current_target = 255;
uint8_t hardcoded_key[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};

uint8_t reassembly_buffer[5000];
uint32_t chunks_received_mask = 0;
int64_t last_chunk_time = 0;

uint8_t my_sign_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t my_sign_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

// --- APP MAIN ---
extern "C" void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init();
    }
    load_node_id();
    
    tx_queue = xQueueCreate(10, 200);
    xTaskCreatePinnedToCore(radio_task, "radio", 80000, NULL, 5, NULL, 1);
    xTaskCreatePinnedToCore(serial_task, "ser", 4096, NULL, 5, NULL, 0);
}