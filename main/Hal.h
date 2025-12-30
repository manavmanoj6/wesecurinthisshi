#ifndef HAL_H
#define HAL_H

#include "Config.h"

// RadioLib Definitions manually included if not in library path
#define INPUT 0x01
#define OUTPUT 0x02
#define LOW 0x0
#define HIGH 0x1
#define RISING 0x01
#define FALLING 0x02
#include "RadioLib.h"

class EspHal : public RadioLibHal {
private: 
    int _sck, _miso, _mosi;
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

#endif