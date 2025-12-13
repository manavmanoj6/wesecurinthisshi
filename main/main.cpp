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
#include "driver/gpio.h"
#include "driver/uart.h"

// ----------------------------------------------------------------------------
// 0. Global Definitions (Moved to TOP to fix "Undeclared" errors)
// ----------------------------------------------------------------------------
#define TAG_CRYPTO "CRYPTO"
#define TAG_RADIO  "RADIO"
#define TAG_APP    "APP"

// Wiring Config
#define LORA_NSS    5
#define LORA_DIO0   2
#define LORA_RST    27
#define LORA_DIO1   4
#define LORA_SCK    18
#define LORA_MISO   19
#define LORA_MOSI   23

// Packet Types
#define TYPE_CHAT           0x01
#define TYPE_KYBER_PUBKEY   0x02 
#define TYPE_KYBER_CIPHER   0x03 

// ----------------------------------------------------------------------------
// 1. C Compatibility Wrappers
// ----------------------------------------------------------------------------
extern "C" {
    #include "ascon.h"
    #include "crypto_aead.h"
    #include "mlkem_api.h"   // Kyber-512
    #include "randombytes.h"
    void app_main(void);
}

// ----------------------------------------------------------------------------
// 2. Hardware Abstraction (Bit-Bang SPI)
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
// 3. Data Structures
// ----------------------------------------------------------------------------

// The Header (Unencrypted)
typedef struct __attribute__((packed)) {
    uint8_t  type;          
    uint8_t  chunk_id;      
    uint8_t  total_chunks;  
    uint16_t data_len;      
    uint8_t  payload[240];  
} LoRaFrame_t;

// The "Chat" Payload (Encrypted part inside payload[])
typedef struct __attribute__((packed)) {
    uint16_t seq_num;
    uint16_t ct_len;
    uint8_t  nonce[16];
    uint8_t  auth_tag[16];
    uint8_t  ciphertext[200]; 
} EncryptedChat_t;

// Globals
EspHal* hal = NULL;
SX1276* radio = NULL;
QueueHandle_t tx_queue = NULL;

// Security State
uint8_t current_session_key[32]; 
uint8_t hardcoded_key[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
bool is_secure = false;

// Kyber Buffers
uint8_t kyber_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES]; 
uint8_t kyber_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES]; 
uint8_t reassembly_buffer[2000]; 
uint8_t chunks_received_mask = 0; 

// ----------------------------------------------------------------------------
// 4. Crypto Logic
// ----------------------------------------------------------------------------

void set_key(uint8_t* new_key) {
    memcpy(current_session_key, new_key, 32);
    ESP_LOGI(TAG_APP, ">>> SECURITY UPGRADED! Switched to Quantum-Safe Key. <<<");
    is_secure = true;
}

int ascon_encrypt(EncryptedChat_t* pkt, const uint8_t* msg, uint16_t len) {
    uint8_t temp_nonce[16];
    esp_fill_random(temp_nonce, 16);
    memcpy(pkt->nonce, temp_nonce, 16);
    
    unsigned long long clen;
    int rc = crypto_aead_encrypt(pkt->ciphertext, &clen, msg, len, 
                                 NULL, 0, NULL, temp_nonce, current_session_key);
    if (rc == 0) {
        pkt->ct_len = (uint16_t)(clen - 16);
        memcpy(pkt->auth_tag, pkt->ciphertext + pkt->ct_len, 16);
        return 0;
    }
    return -1;
}

int ascon_decrypt(EncryptedChat_t* pkt, uint8_t* output, uint16_t* out_len) {
    if (pkt->ct_len > 200) return -1;
    uint8_t temp_ct[256];
    memcpy(temp_ct, pkt->ciphertext, pkt->ct_len);
    memcpy(temp_ct + pkt->ct_len, pkt->auth_tag, 16);
    
    unsigned long long mlen;
    int rc = crypto_aead_decrypt(output, &mlen, NULL, temp_ct, 
                                 pkt->ct_len + 16, NULL, 0, pkt->nonce, current_session_key);
    if (rc == 0) {
        *out_len = (uint16_t)mlen;
        output[*out_len] = '\0';
        return 0;
    }
    return -1;
}

// ----------------------------------------------------------------------------
// 5. Fragmentation Engine
// ----------------------------------------------------------------------------

void send_large_data(uint8_t type, uint8_t* data, size_t total_len) {
    int chunk_size = 200; 
    int total_chunks = (total_len + chunk_size - 1) / chunk_size;

    for (int i = 0; i < total_chunks; i++) {
        LoRaFrame_t frame;
        frame.type = type;
        frame.chunk_id = i;
        frame.total_chunks = total_chunks;
        
        int offset = i * chunk_size;
        int remaining = total_len - offset;
        frame.data_len = (remaining > chunk_size) ? chunk_size : remaining;
        
        memcpy(frame.payload, data + offset, frame.data_len);
        
        radio->transmit((uint8_t*)&frame, 5 + frame.data_len);
        
        ESP_LOGI(TAG_RADIO, "Sent Chunk %d/%d (%d bytes)", i+1, total_chunks, frame.data_len);
        vTaskDelay(pdMS_TO_TICKS(250)); // Delay to allow receiver processing
    }
}

// ----------------------------------------------------------------------------
// 6. Tasks
// ----------------------------------------------------------------------------

void serial_task(void *arg) {
    // FIX: Clean UART Initialization
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
    ESP_LOGI("CMD", "Type 'init' to start Kyber Handshake, or just chat.");

    while (1) {
        uint8_t ch;
        if (uart_read_bytes(UART_NUM_0, &ch, 1, 20 / portTICK_PERIOD_MS) > 0) {
            uart_write_bytes(UART_NUM_0, (const char*)&ch, 1); // Echo
            if (ch == '\r' || ch == '\n') {
                if (pos > 0) {
                    line[pos] = '\0';
                    uart_write_bytes(UART_NUM_0, "\r\n", 2);
                    xQueueSend(tx_queue, line, 0);
                    pos = 0;
                }
            } else if (pos < 199) line[pos++] = ch;
        }
    }
}

void radio_task(void *arg) {
    hal = new EspHal(LORA_SCK, LORA_MISO, LORA_MOSI);
    hal->init();
    radio = new SX1276(new Module(hal, LORA_NSS, LORA_DIO0, LORA_RST, LORA_DIO1));
    radio->begin(868.0, 125.0, 9, 7, 0x12, 17, 8);
    radio->startReceive();
    
    // Default to hardcoded key initially
    memcpy(current_session_key, hardcoded_key, 32);

    char msg_buf[200];
    LoRaFrame_t tx_frame; 
    uint8_t rx_buf[256];

    while (1) {
        // --- RECEIVE ---
        if (hal->digitalRead(LORA_DIO0) == HIGH) {
            size_t len = radio->getPacketLength();
            radio->readData(rx_buf, len);

            if (len > 5) {
                LoRaFrame_t* rx_frame = (LoRaFrame_t*)rx_buf;
                
                // 1. CHAT MESSAGE
                if (rx_frame->type == TYPE_CHAT) {
                    EncryptedChat_t* chat = (EncryptedChat_t*)rx_frame->payload;
                    uint8_t decrypted[200]; 
                    uint16_t out_len = 0;
                    if (ascon_decrypt(chat, decrypted, &out_len) == 0) {
                        ESP_LOGI(TAG_APP, "[%s]: %s", is_secure ? "SECURE" : "UNSAFE", decrypted);
                    } else {
                        ESP_LOGW(TAG_APP, "[FOE]: Auth Failed");
                    }
                }
                
                // 2. KYBER HANDSHAKE (Chunk Reassembly)
                else if (rx_frame->type == TYPE_KYBER_PUBKEY || rx_frame->type == TYPE_KYBER_CIPHER) {
                    int offset = rx_frame->chunk_id * 200;
                    // Safety check to prevent overflow
                    if (offset + rx_frame->data_len <= sizeof(reassembly_buffer)) {
                        memcpy(reassembly_buffer + offset, rx_frame->payload, rx_frame->data_len);
                        chunks_received_mask |= (1 << rx_frame->chunk_id);
                        
                        // Check completion
                        int expected_chunks = rx_frame->total_chunks;
                        int all_bits_set = (1 << expected_chunks) - 1;
                        
                        if ((chunks_received_mask & all_bits_set) == all_bits_set) {
                            ESP_LOGI(TAG_CRYPTO, "Reassembly Complete! Processing Handshake...");
                            chunks_received_mask = 0; // Reset
                            
                            // A. Received Public Key -> Generate Secret -> Reply
                            if (rx_frame->type == TYPE_KYBER_PUBKEY) {
                                uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES]; 
                                uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];           
                                
                                PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, reassembly_buffer);
                                
                                send_large_data(TYPE_KYBER_CIPHER, ct, sizeof(ct));
                                set_key(ss);
                            }
                            
                            // B. Received Ciphertext -> Decapsulate -> Upgrade
                            else if (rx_frame->type == TYPE_KYBER_CIPHER) {
                                uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
                                
                                if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, reassembly_buffer, kyber_sk) == 0) {
                                    set_key(ss);
                                } else {
                                    ESP_LOGE(TAG_CRYPTO, "Kyber Decap Failed!");
                                }
                            }
                        } else {
                            ESP_LOGI(TAG_RADIO, "RX Chunk %d/%d...", rx_frame->chunk_id + 1, expected_chunks);
                        }
                    }
                }
            }
            radio->startReceive();
        }

        // --- TRANSMIT ---
        if (xQueueReceive(tx_queue, msg_buf, 0) == pdTRUE) {
            // Command: "init" -> Starts Handshake
            if (strcmp(msg_buf, "init") == 0) {
                ESP_LOGI(TAG_CRYPTO, "Starting Handshake... Generating Keys...");
                PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kyber_pk, kyber_sk);
                send_large_data(TYPE_KYBER_PUBKEY, kyber_pk, sizeof(kyber_pk));
            } 
            // Normal Chat
            else {
                tx_frame.type = TYPE_CHAT;
                tx_frame.chunk_id = 0;
                tx_frame.total_chunks = 1;
                
                EncryptedChat_t* chat = (EncryptedChat_t*)tx_frame.payload;
                if (ascon_encrypt(chat, (uint8_t*)msg_buf, strlen(msg_buf)) == 0) {
                    size_t header_sz = (uint8_t*)chat->ciphertext - (uint8_t*)chat;
                    tx_frame.data_len = header_sz + chat->ct_len;
                    radio->transmit((uint8_t*)&tx_frame, 5 + tx_frame.data_len);
                    ESP_LOGI(TAG_APP, "Sent: %s", msg_buf);
                }
            }
            radio->startReceive();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void app_main(void) {
    nvs_flash_init();
    tx_queue = xQueueCreate(10, 200);
    // Increased stack for Kyber math
    xTaskCreatePinnedToCore(radio_task, "radio", 24000, NULL, 5, NULL, 1);
    xTaskCreatePinnedToCore(serial_task, "ser", 4096, NULL, 5, NULL, 0);
}