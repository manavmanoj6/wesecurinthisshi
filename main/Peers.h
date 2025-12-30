#ifndef PEERS_H
#define PEERS_H

#include "Config.h"

// --- FIX: Extern declarations WITH SIZES so 'sizeof' works ---
extern uint8_t my_sign_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
extern uint8_t my_sign_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
extern uint8_t hardcoded_key[32];
// -------------------------------------------------------------

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
            // Now 'sizeof' will work because the extern has the size
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
        // Update existing
        for(int i=0; i<MAX_PEERS; i++) {
            if (peers[i].id == nodeId) {
                memcpy(peers[i].session_key, newKey, 32);
                peers[i].is_secure = true;
                peers[i].active = true;
                ESP_LOGI(TAG_CRYPTO, "Key Updated for Node %d", nodeId);
                return;
            }
        }
        // Add new
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

#endif