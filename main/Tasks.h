#ifndef TASKS_H
#define TASKS_H

#include "Shared.h"
#include "Storage.h"

// Internal Buffers for Tasks
static uint8_t large_send_buf[3500]; 
static uint8_t pending_kyber_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

// --- Helpers ---
int ascon_encrypt(EncryptedChat_t* pkt, const uint8_t* msg, uint16_t len, uint8_t* key) {
    uint8_t temp_nonce[16]; esp_fill_random(temp_nonce, 16); memcpy(pkt->nonce, temp_nonce, 16);
    unsigned long long clen;
    if (crypto_aead_encrypt(pkt->ciphertext, &clen, msg, len, NULL, 0, NULL, temp_nonce, key) == 0) {
        pkt->ct_len = (uint16_t)(clen - 16); memcpy(pkt->auth_tag, pkt->ciphertext + pkt->ct_len, 16); return 0;
    } return -1;
}

int ascon_decrypt(EncryptedChat_t* pkt, uint8_t* output, uint16_t* out_len, uint8_t* key) {
    if (pkt->ct_len > 160) return -1;
    uint8_t temp_ct[256]; memcpy(temp_ct, pkt->ciphertext, pkt->ct_len); memcpy(temp_ct + pkt->ct_len, pkt->auth_tag, 16);
    unsigned long long mlen;
    if (crypto_aead_decrypt(output, &mlen, NULL, temp_ct, pkt->ct_len + 16, NULL, 0, pkt->nonce, key) == 0) {
        *out_len = (uint16_t)mlen; output[*out_len] = '\0'; return 0;
    } return -1;
}

void send_large_data(uint8_t target, uint8_t type, uint8_t* data, size_t total_len) {
    int chunk_size = 200; int total_chunks = (total_len + chunk_size - 1) / chunk_size;
    for (int i = 0; i < total_chunks; i++) {
        LoRaFrame_t frame; frame.to_id = target; frame.from_id = my_node_id; frame.type = type;
        frame.chunk_id = i; frame.total_chunks = total_chunks;
        int offset = i * chunk_size; int remaining = total_len - offset;
        frame.data_len = (remaining > chunk_size) ? chunk_size : remaining;
        memcpy(frame.payload, data + offset, frame.data_len);
        radio->transmit((uint8_t*)&frame, 7 + frame.data_len);
        ESP_LOGI(TAG_RADIO, "Sent Chunk %d/%d to Node %d", i+1, total_chunks, target);
        // Balanced Mode Delay
        if (i < total_chunks - 1) vTaskDelay(pdMS_TO_TICKS(150)); else vTaskDelay(pdMS_TO_TICKS(50));
    }
}

// --- TASKS ---
void serial_task(void *arg) {
    uart_config_t uart_config = {}; uart_config.baud_rate = 115200; uart_config.data_bits = UART_DATA_8_BITS;
    uart_config.parity = UART_PARITY_DISABLE; uart_config.stop_bits = UART_STOP_BITS_1;
    uart_config.flow_ctrl = UART_HW_FLOWCTRL_DISABLE; uart_config.source_clk = UART_SCLK_APB;
    uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0); uart_param_config(UART_NUM_0, &uart_config);
    char line[200]; int pos = 0;
    vTaskDelay(pdMS_TO_TICKS(3000)); 
    ESP_LOGI("CMD", "Ready. Commands: 'reset', 'setid <n>', 'to <n>', 'init'");
    while (1) {
        uint8_t ch;
        if (uart_read_bytes(UART_NUM_0, &ch, 1, 20/portTICK_PERIOD_MS) > 0) {
            uart_write_bytes(UART_NUM_0, (const char*)&ch, 1);
            if (ch == '\r' || ch == '\n') {
                if (pos > 0) {
                    line[pos] = '\0'; uart_write_bytes(UART_NUM_0, "\r\n", 2);
                    if (strcmp(line, "reset") == 0) peerMgr.resetAll();
                    else if (strncmp(line, "setid ", 6) == 0) save_node_id(atoi(&line[6]));
                    else if (strncmp(line, "to ", 3) == 0) { current_target = atoi(&line[3]); ESP_LOGI("CMD", "Target: %d", current_target); }
                    else xQueueSend(tx_queue, line, 0);
                    pos = 0;
                }
            } else if (pos < 199) line[pos++] = ch;
        }
    }
}

void radio_task(void *arg) {
    peerMgr.initIdentity();
    hal = new EspHal(LORA_SCK, LORA_MISO, LORA_MOSI); hal->init();
    radio = new SX1276(new Module(hal, LORA_NSS, LORA_DIO0, LORA_RST, LORA_DIO1));
    ESP_LOGI(TAG_RADIO, "Connecting...");
    while (radio->begin(868.0, 250.0, 8, 5, 0x12, 17, 8) != RADIOLIB_ERR_NONE) vTaskDelay(pdMS_TO_TICKS(1000));
    ESP_LOGI(TAG_RADIO, ">>> RADIO READY <<<");
    radio->startReceive();

    char msg_buf[200]; LoRaFrame_t tx_frame; uint8_t rx_buf[256];
    while (1) {
        if (chunks_received_mask != 0 && (esp_timer_get_time() - last_chunk_time > 3000000)) chunks_received_mask = 0;
        
        // RECEIVE
        if (hal->digitalRead(LORA_DIO0) == HIGH) {
            size_t len = radio->getPacketLength();
            if (len > 7 && len < 256) {
                radio->readData(rx_buf, len);
                LoRaFrame_t* rx = (LoRaFrame_t*)rx_buf;
                if (rx->to_id == my_node_id || rx->to_id == BROADCAST_ID) {
                    if (rx->type == TYPE_CHAT) {
                        EncryptedChat_t* chat = (EncryptedChat_t*)rx->payload;
                        uint8_t dec[200]; uint16_t dlen = 0;
                        if (ascon_decrypt(chat, dec, &dlen, peerMgr.getKey(rx->from_id)) == 0)
                            ESP_LOGI(TAG_APP, "[Node %d %s]: %s", rx->from_id, peerMgr.isSecure(rx->from_id)?"SECURE":"UNSAFE", dec);
                        else ESP_LOGW(TAG_APP, "Auth Failed");
                    } else if (rx->type == TYPE_HANDSHAKE || rx->type == TYPE_HANDSHAKE_ACK) {
                        int offset = rx->chunk_id * 200;
                        if (offset + rx->data_len < sizeof(reassembly_buffer)) {
                            memcpy(reassembly_buffer + offset, rx->payload, rx->data_len);
                            chunks_received_mask |= (1 << rx->chunk_id); last_chunk_time = esp_timer_get_time();
                            if ((chunks_received_mask & ((1 << rx->total_chunks) - 1)) == ((1 << rx->total_chunks) - 1)) {
                                chunks_received_mask = 0; ESP_LOGI(TAG_CRYPTO, "Handshake Reassembled.");
                                uint8_t* ptr = reassembly_buffer;
                                if (rx->type == TYPE_HANDSHAKE) {
                                    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES]; uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
                                    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, ptr);
                                    memcpy(large_send_buf, ct, sizeof(ct)); size_t slen;
                                    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(large_send_buf + sizeof(ct), &slen, ct, sizeof(ct), my_sign_sk);
                                    send_large_data(rx->from_id, TYPE_HANDSHAKE_ACK, large_send_buf, sizeof(ct) + slen);
                                    peerMgr.updateSessionKey(rx->from_id, ss);
                                } else {
                                    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
                                    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ptr, pending_kyber_sk) == 0) {
                                        peerMgr.updateSessionKey(rx->from_id, ss); ESP_LOGI(TAG_APP, ">>> SECURE LINK ESTABLISHED <<<");
                                    } else ESP_LOGE(TAG_CRYPTO, "Decap Failed");
                                }
                            }
                        }
                    }
                }
            } else radio->readData(rx_buf, 0);
            radio->startReceive();
        }

        // TRANSMIT
        if (xQueueReceive(tx_queue, msg_buf, 0) == pdTRUE) {
            if (strcmp(msg_buf, "init") == 0) {
                 if (current_target == 255) ESP_LOGE(TAG_APP, "Set target first!");
                 else {
                     uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES]; uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
                     PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk); memcpy(pending_kyber_sk, sk, sizeof(sk));
                     memcpy(large_send_buf, pk, sizeof(pk)); size_t slen;
                     PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(large_send_buf + sizeof(pk), &slen, pk, sizeof(pk), my_sign_sk);
                     send_large_data(current_target, TYPE_HANDSHAKE, large_send_buf, sizeof(pk) + slen);
                 }
            } else {
                tx_frame.type = TYPE_CHAT; tx_frame.chunk_id = 0; tx_frame.total_chunks = 1;
                EncryptedChat_t* chat = (EncryptedChat_t*)tx_frame.payload;
                if (ascon_encrypt(chat, (uint8_t*)msg_buf, strlen(msg_buf), peerMgr.getKey(current_target)) == 0) {
                    tx_frame.to_id = current_target; tx_frame.from_id = my_node_id;
                    tx_frame.data_len = (uint8_t*)chat->ciphertext - (uint8_t*)chat + chat->ct_len;
                    radio->transmit((uint8_t*)&tx_frame, 7 + tx_frame.data_len); ESP_LOGI(TAG_APP, "Sent: %s", msg_buf);
                }
            }
            radio->startReceive();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
#endif