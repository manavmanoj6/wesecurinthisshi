#ifndef STORAGE_H
#define STORAGE_H

#include "Shared.h"

void save_node_id(uint8_t id) {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        nvs_set_u8(my_handle, "node_id", id);
        nvs_commit(my_handle);
        nvs_close(my_handle);
        my_node_id = id;
        ESP_LOGI(TAG_CONF, "Node ID updated to %d", id);
    }
}

void load_node_id() {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
        uint8_t stored_id = 0;
        if (nvs_get_u8(my_handle, "node_id", &stored_id) == ESP_OK) {
            my_node_id = stored_id;
        }
        nvs_close(my_handle);
    }
}

#endif