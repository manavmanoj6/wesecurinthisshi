#ifndef UI_H
#define UI_H

#define LGFX_USE_V1
#include <LovyanGFX.hpp>

class LGFX : public lgfx::LGFX_Device
{
    lgfx::Panel_ST7789      _panel_instance;
    lgfx::Bus_SPI           _bus_instance;
    lgfx::Touch_XPT2046     _touch_instance;

public:
    LGFX(void);
};

void ui_init();
void addMessage(const char* msg, bool isSelf);
void ui_task(void *arg);
void discoveredContact(uint8_t node_id);

#endif // UI_H
