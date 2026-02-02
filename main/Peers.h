#ifndef PEERS_H
#define PEERS_H

#include "Config.h"

#define IS_GROUP_ID(id) (id >= 200 && id <= 250)
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

    // NEW: Structure to hold a "Contact List" for a group
    struct GroupEntry {
        uint8_t id;             // The Group ID (e.g., 201)
        uint8_t members[10];    // Max 10 members per group
        uint8_t count;          // How many members currently in it
        bool active;
    };

    PeerEntry peers[MAX_PEERS];
    GroupEntry groups[5]; // Allow up to 5 different groups

public:
   PeerManager() { resetAll(); }

    void resetAll() {
        for(int i=0; i<MAX_PEERS; i++) { peers[i].active = false; peers[i].is_secure = false; }
        // Reset Groups
        for(int i=0; i<5; i++) { groups[i].active = false; groups[i].count = 0; }
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
    
    // --- NEW: Group Management Functions ---

    // Command: "Make Group 201 with Nodes 2, 3, 4"
    void createGroup(uint8_t groupId) {
        if (!IS_GROUP_ID(groupId)) return;
        
        // Find empty slot or existing slot
        int idx = -1;
        for(int i=0; i<5; i++) {
            if (groups[i].id == groupId) { idx = i; break; } // Update existing
            if (!groups[i].active && idx == -1) idx = i;     // Found empty
        }

        if (idx != -1) {
            groups[idx].id = groupId;
            groups[idx].active = true;
            groups[idx].count = 0; // Reset members
            ESP_LOGI(TAG_CONF, "Created Group %d", groupId);
        }
    }

    void addToGroup(uint8_t groupId, uint8_t nodeId) {
        for(int i=0; i<5; i++) {
            if (groups[i].active && groups[i].id == groupId) {
                if (groups[i].count < 10) {
                    groups[i].members[groups[i].count++] = nodeId;
                    ESP_LOGI(TAG_CONF, "Added Node %d to Group %d", nodeId, groupId);
                }
                return;
            }
        }
    }

    int getGroupMembers(uint8_t groupId, uint8_t* out_list) {
        for(int i=0; i<5; i++) {
            if (groups[i].active && groups[i].id == groupId) {
                memcpy(out_list, groups[i].members, groups[i].count);
                return groups[i].count;
            }
        }
        return 0; // Group not found
    }

    bool isSecure(uint8_t nodeId) {
        for(int i=0; i<MAX_PEERS; i++) {
            if (peers[i].active && peers[i].id == nodeId) return peers[i].is_secure;
        }
        return false;
    }
};

#endif