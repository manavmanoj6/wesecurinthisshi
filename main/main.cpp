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

// ----------------------------------------------------------------------------
// 0. Global Config
// ----------------------------------------------------------------------------
#define TAG_CRYPTO "CRYPTO"
#define TAG_RADIO  "RADIO"
#define TAG_APP    "APP"
#define TAG_CONF   "CONFIG"

// LORA PINS
#define LORA_NSS    5
#define LORA_DIO0   2   
#define LORA_RST    27
#define LORA_DIO1   4
#define LORA_SCK    18
#define LORA_MISO   19
#define LORA_MOSI   23

// Packet Types
#define TYPE_CHAT           0x01
#define TYPE_HANDSHAKE      0x02  
#define TYPE_HANDSHAKE_ACK  0x03

#define BROADCAST_ID 255
#define MAX_PEERS 10

// C-Linkage Wrappers for Crypto Libraries
extern "C" {
    #include "ascon.h"
    #include "crypto_aead.h"
    #include "mlkem_api.h"   
    #include "mldsa_api.h"   
    #include "randombytes.h"
}

// ----------------------------------------------------------------------------
// 1. Hardware Abstraction
// ----------------------------------------------------------------------------
#define INPUT 0x01
#define OUTPUT 0x02
#define LOW 0x0
#define HIGH 0x1
#define RISING 0x01
#define FALLING 0x02
#include "RadioLib.h"

class EspHal : public RadioLibHal {
private: int _sck, _miso, _mosi;
public:
    EspHal(int sck, int miso, int mosi) : RadioLibHal(INPUT, OUTPUT, LOW, HIGH, RISING, FALLING) {
        _sck = sck; _miso = miso; _mosi = mosi;
    }
    void init() {
        gpio_reset_pin((gpio_num_t)_sck); gpio_set_direction((gpio_num_t)_sck, GPIO_MODE_OUTPUT);
        gpio_reset_pin((gpio_num_t)_mosi); gpio_set_direction((gpio_num_t)_mosi, GPIO_MODE_OUTPUT);
        gpio_reset_pin((gpio_num_t)_miso); gpio_set_direction((gpio_num_t)_miso, GPIO_MODE_INPUT);
        gpio_set_pull_mode((gpio_num_t)_miso, GPIO_PULLUP_ONLY);
        gpio_set_level((gpio_num_t)_sck, 0); gpio_set_level((gpio_num_t)_mosi, 0);
    }
    void spiTransfer(uint8_t* out, size_t len, uint8_t* in) override {
        for (size_t i = 0; i < len; i++) {
            uint8_t b_out = out[i]; uint8_t b_in = 0;
            for (int bit = 7; bit >= 0; bit--) {
                gpio_set_level((gpio_num_t)_mosi, (b_out >> bit) & 1);
                esp_rom_delay_us(1);
                gpio_set_level((gpio_num_t)_sck, 1);
                if (gpio_get_level((gpio_num_t)_miso)) b_in |= (1 << bit);
                esp_rom_delay_us(1);
                gpio_set_level((gpio_num_t)_sck, 0);
            }
            in[i] = b_in;
        }
    }
    void pinMode(uint32_t pin, uint32_t mode) override {
        if (pin != RADIOLIB_NC) {
            gpio_reset_pin((gpio_num_t)pin);
            gpio_set_direction((gpio_num_t)pin, (mode == INPUT) ? GPIO_MODE_INPUT : GPIO_MODE_OUTPUT);
        }
    }
    void digitalWrite(uint32_t pin, uint32_t value) override {
        if (pin != RADIOLIB_NC) gpio_set_level((gpio_num_t)pin, value);
    }
    uint32_t digitalRead(uint32_t pin) override {
        return (pin != RADIOLIB_NC) ? gpio_get_level((gpio_num_t)pin) : 0;
    }
    void delay(unsigned long ms) override { vTaskDelay(pdMS_TO_TICKS(ms)); }
    void delayMicroseconds(unsigned long us) override { esp_rom_delay_us(us); }
    unsigned long millis() override { return (unsigned long)(esp_timer_get_time() / 1000); }
    unsigned long micros() override { return (unsigned long)(esp_timer_get_time()); }
    long pulseIn(uint32_t pin, uint32_t state, unsigned long timeout) override { return 0; }
    void attachInterrupt(uint32_t i, void (*c)(void), uint32_t m) override {}
    void detachInterrupt(uint32_t i) override {}
    void spiBegin() override {} void spiBeginTransaction() override {} 
    void spiEndTransaction() override {} void spiEnd() override {}
};

// ----------------------------------------------------------------------------
// 2. Data Structures & Globals
// ----------------------------------------------------------------------------
typedef struct __attribute__((packed)) {
    uint8_t  to_id;       
    uint8_t  from_id;     
    uint8_t  type;          
    uint8_t  chunk_id;      
    uint8_t  total_chunks;  
    uint16_t data_len;      
    uint8_t  payload[200];  
} LoRaFrame_t;

typedef struct __attribute__((packed)) {
    uint16_t seq_num;
    uint16_t ct_len;
    uint8_t  nonce[16];
    uint8_t  auth_tag[16];
    uint8_t  ciphertext[160]; 
} EncryptedChat_t;

EspHal* hal = NULL;
SX1276* radio = NULL;
QueueHandle_t tx_queue = NULL;

uint8_t my_node_id = 1;         
uint8_t current_target = 255;   
uint8_t hardcoded_key[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};

// --- GLOBAL BUFFERS ---
uint8_t reassembly_buffer[5000]; 
uint32_t chunks_received_mask = 0; 
int64_t last_chunk_time = 0; 

uint8_t my_sign_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES]; 
uint8_t my_sign_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES]; 
static uint8_t large_send_buf[3500]; 
static uint8_t pending_kyber_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

// ----------------------------------------------------------------------------
// 3. Peer Manager
// ----------------------------------------------------------------------------
class PeerManager {
private:
    struct PeerEntry {
        uint8_t id;
        uint8_t session_key[32];      
        bool is_secure;
        bool active;
    };
    PeerEntry peers[MAX_PEERS];

public:
    PeerManager() {
        resetAll();
    }

    void resetAll() {
        for(int i=0; i<MAX_PEERS; i++) {
            peers[i].active = false;
            peers[i].is_secure = false;
            memset(peers[i].session_key, 0, 32); 
        }
        ESP_LOGW(TAG_CRYPTO, "All Keys Wiped. System Reset.");
    }

    void initIdentity() {
        nvs_handle_t handle;
        if (nvs_open("identity", NVS_READWRITE, &handle) == ESP_OK) {
            size_t size = sizeof(my_sign_pk);
            if (nvs_get_blob(handle, "pk", my_sign_pk, &size) != ESP_OK) {
                ESP_LOGW(TAG_CRYPTO, "Generating Identity (First Run)...");
                PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(my_sign_pk, my_sign_sk);
                nvs_set_blob(handle, "pk", my_sign_pk, sizeof(my_sign_pk));
                nvs_set_blob(handle, "sk", my_sign_sk, sizeof(my_sign_sk));
                nvs_commit(handle);
            } else {
                size_t sk_size = sizeof(my_sign_sk);
                nvs_get_blob(handle, "sk", my_sign_sk, &sk_size);
            }
            nvs_close(handle);
        }
    }

    uint8_t* getKey(uint8_t nodeId) {
        for(int i=0; i<MAX_PEERS; i++) {
            if (peers[i].active && peers[i].id == nodeId) return peers[i].session_key;
        }
        return hardcoded_key;
    }

    void updateSessionKey(uint8_t nodeId, uint8_t* newKey) {
        for(int i=0; i<MAX_PEERS; i++) {
            if (peers[i].id == nodeId) {
                memcpy(peers[i].session_key, newKey, 32);
                peers[i].is_secure = true;
                peers[i].active = true;
                ESP_LOGI(TAG_CRYPTO, "Key Installed for Node %d", nodeId);
                return;
            }
        }
        // New peer
        for(int i=0; i<MAX_PEERS; i++) {
            if (!peers[i].active) {
                peers[i].id = nodeId;
                peers[i].active = true;
                memcpy(peers[i].session_key, newKey, 32);
                peers[i].is_secure = true;
                ESP_LOGI(TAG_CRYPTO, "New Key Installed for Node %d", nodeId);
                return;
            }
        }
    }
    
    bool isSecure(uint8_t nodeId) {
        for(int i=0; i<MAX_PEERS; i++) {
            if (peers[i].active && peers[i].id == nodeId) return peers[i].is_secure;
        }
        return false;
    }
};
PeerManager peerMgr;

// ----------------------------------------------------------------------------
// 4. Crypto Logic
// ----------------------------------------------------------------------------
int ascon_encrypt(EncryptedChat_t* pkt, const uint8_t* msg, uint16_t len, uint8_t* key) {
    uint8_t temp_nonce[16];
    esp_fill_random(temp_nonce, 16);
    memcpy(pkt->nonce, temp_nonce, 16);
    unsigned long long clen;
    int rc = crypto_aead_encrypt(pkt->ciphertext, &clen, msg, len, NULL, 0, NULL, temp_nonce, key);
    if (rc == 0) {
        pkt->ct_len = (uint16_t)(clen - 16);
        memcpy(pkt->auth_tag, pkt->ciphertext + pkt->ct_len, 16);
        return 0;
    } return -1;
}

int ascon_decrypt(EncryptedChat_t* pkt, uint8_t* output, uint16_t* out_len, uint8_t* key) {
    if (pkt->ct_len > 160) return -1;
    uint8_t temp_ct[256];
    memcpy(temp_ct, pkt->ciphertext, pkt->ct_len);
    memcpy(temp_ct + pkt->ct_len, pkt->auth_tag, 16);
    unsigned long long mlen;
    int rc = crypto_aead_decrypt(output, &mlen, NULL, temp_ct, pkt->ct_len + 16, NULL, 0, pkt->nonce, key);
    if (rc == 0) { *out_len = (uint16_t)mlen; output[*out_len] = '\0'; return 0; } return -1;
}

// ----------------------------------------------------------------------------
// 5. Config & Transmission
// ----------------------------------------------------------------------------
void save_node_id(uint8_t id) {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        nvs_set_u8(my_handle, "node_id", id);
        nvs_commit(my_handle); nvs_close(my_handle);
        my_node_id = id;
        ESP_LOGI(TAG_CONF, "Node ID updated to %d", id);
    }
}
void load_node_id() {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        uint8_t stored_id = 0;
        if (nvs_get_u8(my_handle, "node_id", &stored_id) == ESP_OK) my_node_id = stored_id;
        nvs_close(my_handle);
    }
}

void send_large_data(uint8_t target, uint8_t type, uint8_t* data, size_t total_len) {
    int chunk_size = 200; 
    int total_chunks = (total_len + chunk_size - 1) / chunk_size;

    for (int i = 0; i < total_chunks; i++) {
        LoRaFrame_t frame;
        frame.to_id = target;       
        frame.from_id = my_node_id; 
        frame.type = type;
        frame.chunk_id = i;
        frame.total_chunks = total_chunks;
        
        int offset = i * chunk_size;
        int remaining = total_len - offset;
        frame.data_len = (remaining > chunk_size) ? chunk_size : remaining;
        memcpy(frame.payload, data + offset, frame.data_len);
        
        radio->transmit((uint8_t*)&frame, 7 + frame.data_len);
        ESP_LOGI(TAG_RADIO, "Sent Chunk %d/%d to Node %d", i+1, total_chunks, target);
        
        // [CONFIG] Balanced Mode Delay (SF8, BW250)
        if (i < total_chunks - 1) vTaskDelay(pdMS_TO_TICKS(150)); 
        else vTaskDelay(pdMS_TO_TICKS(50));
    }
}

// ----------------------------------------------------------------------------
// 6. Tasks
// ----------------------------------------------------------------------------
void serial_task(void *arg) {
    uart_config_t uart_config = {};
    uart_config.baud_rate = 115200;
    uart_config.data_bits = UART_DATA_8_BITS;
    uart_config.parity = UART_PARITY_DISABLE;
    uart_config.stop_bits = UART_STOP_BITS_1;
    uart_config.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
    uart_config.source_clk = UART_SCLK_APB;
    uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0);
    uart_param_config(UART_NUM_0, &uart_config);
    
    char line[200]; int pos = 0;
    vTaskDelay(pdMS_TO_TICKS(3000)); 
    ESP_LOGI("CMD", "Ready. Commands: 'reset', 'setid <n>', 'to <n>', 'init'");

    while (1) {
        uint8_t ch;
        int len = uart_read_bytes(UART_NUM_0, &ch, 1, 20/portTICK_PERIOD_MS);
        if (len > 0) {
            uart_write_bytes(UART_NUM_0, (const char*)&ch, 1);
            if (ch == '\r' || ch == '\n') {
                if (pos > 0) {
                    line[pos] = '\0'; uart_write_bytes(UART_NUM_0, "\r\n", 2);
                    
                    if (strcmp(line, "reset") == 0) {
                        peerMgr.resetAll();
                    } else if (strncmp(line, "setid ", 6) == 0) {
                        int id = atoi(&line[6]);
                        if (id > 0 && id < 255) save_node_id(id);
                    } else if (strncmp(line, "to ", 3) == 0) {
                        int id = atoi(&line[3]);
                        if (id > 0 && id < 255) { current_target = (uint8_t)id; ESP_LOGI("CMD", "Target: %d", id); }
                    } else xQueueSend(tx_queue, line, 0);
                    pos = 0;
                }
            } else if (pos < 199) line[pos++] = ch;
        } 
    }
}

void radio_task(void *arg) {
    ESP_LOGI(TAG_CRYPTO, "Initializing Identity... (Wait 2s)");
    peerMgr.initIdentity(); 
    ESP_LOGI(TAG_CRYPTO, "Identity Ready.");

    hal = new EspHal(LORA_SCK, LORA_MISO, LORA_MOSI);
    hal->init();
    radio = new SX1276(new Module(hal, LORA_NSS, LORA_DIO0, LORA_RST, LORA_DIO1));
    
    // [CONFIG] Balanced Mode (SF8, BW250) -> ~1km Range
    ESP_LOGI(TAG_RADIO, "Connecting to Radio...");
    int state = radio->begin(868.0, 250.0, 8, 5, 0x12, 17, 8);
    while (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG_RADIO, "Hardware Fail! Code: %d", state);
        vTaskDelay(pdMS_TO_TICKS(2000));
        state = radio->begin(868.0, 250.0, 8, 5, 0x12, 17, 8);
    }
    ESP_LOGI(TAG_RADIO, ">>> RADIO CONNECTED (BALANCED 1KM MODE) <<<");
    
    radio->startReceive();
    
    char msg_buf[200];
    LoRaFrame_t tx_frame; 
    uint8_t rx_buf[256];

    while (1) {
        // Timeout check (3s for Balanced Mode)
        if (chunks_received_mask != 0 && (esp_timer_get_time() - last_chunk_time > 3000000)) {
            chunks_received_mask = 0;
            ESP_LOGW(TAG_RADIO, "Handshake Timed Out. Resetting.");
        }

        if (hal->digitalRead(LORA_DIO0) == HIGH) {
            size_t len = radio->getPacketLength();
            if (len > 0 && len < 256) {
                radio->readData(rx_buf, len);

                if (len > 7) {
                    LoRaFrame_t* rx_frame = (LoRaFrame_t*)rx_buf;
                    
                    if (rx_frame->to_id == my_node_id || rx_frame->to_id == BROADCAST_ID) {
                        
                        if (rx_frame->type == TYPE_CHAT) {
                            EncryptedChat_t* chat = (EncryptedChat_t*)rx_frame->payload;
                            uint8_t decrypted[200]; uint16_t out_len = 0;
                            uint8_t* key = peerMgr.getKey(rx_frame->from_id);
                            bool secured = peerMgr.isSecure(rx_frame->from_id);
                            if (ascon_decrypt(chat, decrypted, &out_len, key) == 0) {
                                ESP_LOGI(TAG_APP, "[Node %d %s]: %s", rx_frame->from_id, secured?"SECURE":"UNSAFE", decrypted);
                            } else ESP_LOGW(TAG_APP, "Auth Failed (Key Mismatch)");
                        }
                        else if (rx_frame->type == TYPE_HANDSHAKE || rx_frame->type == TYPE_HANDSHAKE_ACK) {
                            int offset = rx_frame->chunk_id * 200;
                            if (offset + rx_frame->data_len < sizeof(reassembly_buffer)) {
                                memcpy(reassembly_buffer + offset, rx_frame->payload, rx_frame->data_len);
                                chunks_received_mask |= (1 << rx_frame->chunk_id);
                                last_chunk_time = esp_timer_get_time(); 
                                
                                if ((chunks_received_mask & ((1 << rx_frame->total_chunks) - 1)) == ((1 << rx_frame->total_chunks) - 1)) {
                                    chunks_received_mask = 0;
                                    ESP_LOGI(TAG_CRYPTO, "Handshake Reassembled. Verifying...");
                                    
                                    uint8_t* msg_ptr = reassembly_buffer;
                                    
                                    if (rx_frame->type == TYPE_HANDSHAKE) {
                                        uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES]; 
                                        uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];           
                                        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, msg_ptr);
                                        
                                        memcpy(large_send_buf, ct, sizeof(ct));
                                        size_t sig_len_out;
                                        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(large_send_buf + sizeof(ct), &sig_len_out, ct, sizeof(ct), my_sign_sk);
                                        
                                        send_large_data(rx_frame->from_id, TYPE_HANDSHAKE_ACK, large_send_buf, sizeof(ct) + sig_len_out);
                                        peerMgr.updateSessionKey(rx_frame->from_id, ss);
                                    }
                                    else { 
                                        uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
                                        if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, msg_ptr, pending_kyber_sk) == 0) {
                                            peerMgr.updateSessionKey(rx_frame->from_id, ss);
                                            ESP_LOGI(TAG_APP, ">>> SECURE LINK ESTABLISHED <<<");
                                        } else {
                                            ESP_LOGE(TAG_CRYPTO, "Kyber Decap Failed! (Corrupted Packet)");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else radio->readData(rx_buf, 0); 
            radio->startReceive();
        }

        if (xQueueReceive(tx_queue, msg_buf, 0) == pdTRUE) {
            if (strcmp(msg_buf, "init") == 0) {
                if (current_target == 255) {
                    ESP_LOGE(TAG_APP, "ERROR: Set target first! 'to <id>'");
                } else {
                    ESP_LOGI(TAG_CRYPTO, "Starting Signed Handshake...");
                    uint8_t k_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
                    uint8_t k_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
                    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(k_pk, k_sk);
                    
                    memcpy(pending_kyber_sk, k_sk, sizeof(k_sk));

                    memcpy(large_send_buf, k_pk, sizeof(k_pk));
                    size_t sig_len;
                    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(large_send_buf + sizeof(k_pk), &sig_len, k_pk, sizeof(k_pk), my_sign_sk);
                    
                    send_large_data(current_target, TYPE_HANDSHAKE, large_send_buf, sizeof(k_pk) + sig_len);
                }
            } 
            else {
                tx_frame.type = TYPE_CHAT;
                tx_frame.chunk_id = 0; tx_frame.total_chunks = 1;
                EncryptedChat_t* chat = (EncryptedChat_t*)tx_frame.payload;
                uint8_t* key = peerMgr.getKey(current_target); 
                if (ascon_encrypt(chat, (uint8_t*)msg_buf, strlen(msg_buf), key) == 0) {
                    tx_frame.to_id = current_target; tx_frame.from_id = my_node_id;
                    size_t header_sz = (uint8_t*)chat->ciphertext - (uint8_t*)chat;
                    tx_frame.data_len = header_sz + chat->ct_len;
                    radio->transmit((uint8_t*)&tx_frame, 7 + tx_frame.data_len);
                    ESP_LOGI(TAG_APP, "Sent: %s", msg_buf);
                }
            }
            radio->startReceive();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// LINKER FIX: extern "C" wrapper
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