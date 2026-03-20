#include "Ui.h"
#include "Shared.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_timer.h"
#include <driver/spi_master.h>

#ifndef HSPI_HOST
#define HSPI_HOST SPI2_HOST
#endif

#ifndef TFT_BLACK
#define TFT_BLACK 0x0000
#define TFT_WHITE 0xFFFF
#define TFT_GREEN 0x07E0
#define TFT_CYAN 0x07FF
#define TFT_DARKGREY 0x4A69
#endif

// Premium Dark Theme Colors
#define TH_BG 0x0821        // Very dark grey/blue
#define TH_KEY 0x31A6       // Dark grey for chiclet keys
#define TH_KEY_DARK 0x18C3  // Slightly darker for special keys
#define TH_ACCENT 0x0419    // Vibrant iMessage Blue
#define TH_ACCENT_GREEN 0x2506 // Send button Green
#define TH_BAR 0x1082       // Header/Footer bar background
#define TH_TEXT 0xFFFF
#define TH_TEXT_DIM 0xCE59

char logBuffer[20][80] = {0};
int logHead = 0;
bool isLogView = false;
bool logsDirty = false;
bool isNumKeyboard = false;
int capsMode = 0; // 0=lower, 1=shift, 2=caps
vprintf_like_t orig_log_vprintf = NULL;

int custom_log_vprintf(const char *fmt, va_list args) {
    char temp[120];
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(temp, sizeof(temp), fmt, args_copy);
    va_end(args_copy);
    if (len > 0) {
        for(int i=0; i<len; i++) if (temp[i] == '\r' || temp[i] == '\n') temp[i] = ' ';
        strncpy(logBuffer[logHead], temp, 79);
        logBuffer[logHead][79] = 0;
        logHead = (logHead + 1) % 20;
        logsDirty = true;
    }
    if (orig_log_vprintf) return orig_log_vprintf(fmt, args);
    return vprintf(fmt, args);
}

LGFX lcd;
LGFX_Sprite chatSprite(&lcd);
char inputBuf[200] = {0};
int inputLen = 0;
int chatOffsetY = 0;

LGFX::LGFX(void) {
    {
        auto cfg = _bus_instance.config();
        cfg.spi_host = HSPI_HOST; // standard HSPI
        cfg.spi_mode = 0;
        cfg.freq_write = 40000000;
        cfg.freq_read  = 16000000;
        cfg.spi_3wire  = false;
        cfg.use_lock   = true;
        cfg.dma_channel = SPI_DMA_CH_AUTO;
        cfg.pin_sclk = 18;
        cfg.pin_mosi = 23;
        cfg.pin_miso = 19;
        cfg.pin_dc   = 2;
        _bus_instance.config(cfg);
        _panel_instance.setBus(&_bus_instance);
    }
    {
        auto cfg = _panel_instance.config();
        cfg.pin_cs           = 5;
        cfg.pin_rst          = 4;
        cfg.pin_busy         = -1;
        cfg.memory_width     = 240;
        cfg.memory_height    = 320;
        cfg.panel_width      = 240;
        cfg.panel_height     = 320;
        cfg.offset_x         = 0;
        cfg.offset_y         = 0;
        cfg.offset_rotation  = 0;
        cfg.dummy_read_pixel = 8;
        cfg.dummy_read_bits  = 1;
        cfg.readable         = true;
        cfg.invert           = true;
        cfg.rgb_order        = false;
        cfg.dlen_16bit       = false;
        cfg.bus_shared       = true;
        _panel_instance.config(cfg);
    }
    {
        auto cfg = _touch_instance.config();
        // Swapped min/max to invert the X-axis mapping!
        cfg.x_min      = 3900;
        cfg.x_max      = 300;
        // Fine-tuned the Y-axis mapping to balance the bottom touch zone
        cfg.y_min      = 300;
        cfg.y_max      = 3550;
        cfg.pin_int    = -1;
        cfg.bus_shared = true;
        cfg.offset_rotation = 0;
        cfg.spi_host = HSPI_HOST;
        cfg.freq = 1000000;
        cfg.pin_sclk = 18;
        cfg.pin_mosi = 23;
        cfg.pin_miso = 19;
        cfg.pin_cs   = 14; // User requested Touch CS on 14
        _touch_instance.config(cfg);
        _panel_instance.setTouch(&_touch_instance);
    }
    setPanel(&_panel_instance);
}

void drawKeyboard() {
    lcd.fillRect(0, 200, 240, 120, TH_BG);
    const char* rowsAlphaUpper[3] = {"QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"};
    const char* rowsAlphaLower[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
    const char* rowsNum[3]        = {"1234567890", "@#%&*-+()!", ".,:;'\"/?"};
    const char** rows = isNumKeyboard ? rowsNum : ((capsMode > 0) ? rowsAlphaUpper : rowsAlphaLower);
    int yOff = 202;
    for(int r=0; r<3; r++) {
        int keys = strlen(rows[r]);
        int kw = 240 / keys;
        for(int c=0; c<keys; c++) {
            int x = c * kw;
            int y = yOff + (r * 30);
            lcd.fillRoundRect(x + 2, y + 2, kw - 4, 26, 4, TH_KEY);
            lcd.setCursor(x + kw/2 - 4, y + 8);
            lcd.setTextColor(TH_TEXT);
            lcd.printf("%c", rows[r][c]);
        }
    }
    int bW = 48;
    int bY = yOff + 90;
    lcd.fillRoundRect(2, bY + 2, bW - 4, 26, 6, TH_KEY_DARK);  
    lcd.setTextColor(TH_TEXT);
    lcd.drawString(isNumKeyboard ? "ABC" : "123", 14, bY + 8);
    
    lcd.fillRoundRect(bW + 2, bY + 2, bW - 4, 26, 6, capsMode>0 ? TH_ACCENT : TH_KEY_DARK); 
    const char* shfLbl = (capsMode == 0) ? "shf" : ((capsMode == 1) ? "SHF" : "CAP");
    if (!isNumKeyboard) lcd.drawString(shfLbl, bW + 14, bY + 8);
    
    lcd.fillRoundRect(bW*2 + 2, bY + 2, bW - 4, 26, 6, TH_KEY); 
    lcd.drawString("SPC", bW*2 + 14, bY + 8);
    
    lcd.fillRoundRect(bW*3 + 2, bY + 2, bW - 4, 26, 6, TH_KEY_DARK); 
    lcd.drawString("DEL", bW*3 + 14, bY + 8);
    
    lcd.fillRoundRect(bW*4 + 2, bY + 2, bW - 4, 26, 6, TH_ACCENT_GREEN); 
    lcd.drawString("SND", bW*4 + 14, bY + 8);
}

void addMessage(const char* msg, bool isSelf) {
    if (chatOffsetY > 135) {
        chatSprite.scroll(0, -22);
        chatOffsetY -= 22;
    }
    int len = strlen(msg);
    int tw = (len * 6) + 12; // Text width + padding
    if (tw > 200) tw = 200;
    
    if (isSelf) {
        chatSprite.fillRoundRect(236 - tw, chatOffsetY, tw, 18, 5, TH_ACCENT);
        chatSprite.setTextColor(TH_TEXT);
        chatSprite.setCursor(236 - tw + 6, chatOffsetY + 5);
        chatSprite.printf("%s", msg);
    } else {
        chatSprite.fillRoundRect(4, chatOffsetY, tw, 18, 5, TH_KEY_DARK);
        chatSprite.setTextColor(TH_TEXT);
        chatSprite.setCursor(10, chatOffsetY + 5);
        chatSprite.printf("%s", msg);
    }
    chatOffsetY += 22;
    if (!isLogView) chatSprite.pushSprite(0, 24);
}

void handleTouch(int x, int y) {
    if (y < 20 && x < 80) { // Header touch
        isLogView = !isLogView;
        if (isLogView) {
            lcd.fillScreen(TH_BG);
            lcd.fillRect(0, 0, 240, 24, TH_BAR);
            lcd.fillRoundRect(4, 3, 46, 18, 4, TH_KEY_DARK);
            lcd.setTextColor(TH_TEXT);
            lcd.drawString("BACK", 12, 6);
            lcd.drawString("SYSTEM LOGS", 80, 6);
            logsDirty = true;
        } else {
            lcd.fillScreen(TH_BG);
            lcd.fillRect(0, 0, 240, 24, TH_BAR);
            lcd.fillRoundRect(4, 3, 40, 18, 4, TH_KEY_DARK);
            lcd.setTextColor(TH_TEXT);
            lcd.drawString("LOG", 12, 6);
            lcd.drawString("CORTEX CHAT", 80, 6);
            
            chatSprite.pushSprite(0, 24);
            drawKeyboard();
            lcd.fillRect(0, 174, 240, 26, TH_BAR);
            lcd.fillRoundRect(4, 177, 232, 20, 10, TH_KEY_DARK);
            lcd.setTextColor(TH_TEXT);
            lcd.drawString(inputBuf, 10, 180);
        }
        return;
    }

    if (isLogView) return;

    if (y < 200) return;
    int yOff = 205;
    char pressed = 0;
    const char* rowsAlphaUpper[3] = {"QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"};
    const char* rowsAlphaLower[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
    const char* rowsNum[3]        = {"1234567890", "@#%&*-+()!", ".,:;'\"/?"};
    const char** rows = isNumKeyboard ? rowsNum : ((capsMode > 0) ? rowsAlphaUpper : rowsAlphaLower);
    
    if (y > yOff && y < yOff + 30) {
        int keys = strlen(rows[0]); int kw = 240 / keys; pressed = rows[0][x / kw];
    } else if (y > yOff + 30 && y < yOff + 60) {
        int keys = strlen(rows[1]); int kw = 240 / keys; pressed = rows[1][x / kw];
    } else if (y > yOff + 60 && y < yOff + 90) {
        int keys = strlen(rows[2]); 
        if (x < 240/keys * keys) { int kw = 240/keys; pressed = rows[2][x / kw]; }
    } else if (y > yOff + 90) {
        int bW = 48;
        if (x < bW) { 
            isNumKeyboard = !isNumKeyboard; 
            drawKeyboard(); 
            return; 
        } else if (x < bW*2) {
            if (!isNumKeyboard) {
                capsMode = (capsMode + 1) % 3;
                drawKeyboard();
            }
            return;
        } else if (x < bW*3) {
            pressed = ' ';
        } else if (x < bW*4) {
            pressed = '\b';
        } else {
            pressed = '\r';
        }
    }

    if (pressed == '\b' && inputLen > 0) {
        inputBuf[--inputLen] = 0;
    } else if (pressed == '\r' && inputLen > 0) {
        if (strcmp(inputBuf, "reset") == 0 || strncmp(inputBuf, "setid ", 6) == 0 || strncmp(inputBuf, "mkgroup ", 8) == 0 || strncmp(inputBuf, "add ", 4) == 0 || strncmp(inputBuf, "to ", 3) == 0 || strcmp(inputBuf, "init") == 0) {
            xQueueSend(tx_queue, inputBuf, 0);
        } else {
            addMessage(inputBuf, true);
            ESP_LOGI("CHAT", "My Message: %s", inputBuf); // Force a log entry
            xQueueSend(tx_queue, inputBuf, 0);
        }
        inputLen = 0;
        inputBuf[0] = 0;
    } else if (pressed >= ' ' && inputLen < 198) {
        inputBuf[inputLen++] = pressed;
        inputBuf[inputLen] = 0;
        if (capsMode == 1 && !isNumKeyboard) { // Revert to lowercase after single Shift
            capsMode = 0;
            drawKeyboard();
        }
    }

    lcd.fillRect(0, 174, 240, 26, TH_BAR);
    lcd.fillRoundRect(4, 177, 232, 20, 10, TH_KEY_DARK);
    lcd.setTextColor(TH_TEXT);
    lcd.drawString(inputBuf, 10, 180);

    // Visual feedback for touch
    lcd.fillCircle(x, y, 6, TH_ACCENT);
    vTaskDelay(pdMS_TO_TICKS(40));
    drawKeyboard(); // redraw fully to cleanly erase footprint
    // redraw input bar
    lcd.fillRect(0, 174, 240, 26, TH_BAR);
    lcd.fillRoundRect(4, 177, 232, 20, 10, TH_KEY_DARK);
    lcd.setTextColor(TH_TEXT);
    lcd.drawString(inputBuf, 10, 180);
}

void ui_init() {
    orig_log_vprintf = esp_log_set_vprintf(custom_log_vprintf);
    
    lcd.init();
    lcd.setRotation(0);
    lcd.fillScreen(TH_BG);
    
    // Top Bar
    lcd.fillRect(0, 0, 240, 24, TH_BAR);
    lcd.fillRoundRect(4, 3, 40, 18, 4, TH_KEY_DARK);
    lcd.setTextColor(TH_TEXT);
    lcd.drawString("LOG", 12, 6);
    lcd.drawString("CORTEX CHAT", 80, 6);
    
    chatSprite.createSprite(240, 150);
    chatSprite.fillSprite(TH_BG);
    chatSprite.setTextColor(TH_TEXT_DIM);
    chatSprite.drawString("Connected safely.", 5, 5);
    chatSprite.pushSprite(0, 24); // Display the chat area below header
    chatOffsetY = 22;

    drawKeyboard();
    lcd.fillRect(0, 174, 240, 26, TH_BAR);
    lcd.fillRoundRect(4, 177, 232, 20, 10, TH_KEY_DARK);
}

void ui_task(void *arg) {
    ui_init();
    uint16_t x, y;
    int64_t last_touch = 0;
    while(1) {
        if (isLogView && logsDirty) {
            lcd.fillRect(0, 24, 240, 300, TH_BG);
            lcd.setTextColor(TFT_GREEN);
            int start = logHead;
            int drawY = 25;
            for(int i=0; i<20; i++) {
                if (logBuffer[start][0] != 0) {
                    lcd.drawString(logBuffer[start], 5, drawY);
                    drawY += 15;
                }
                start = (start + 1) % 20;
            }
            logsDirty = false;
        }

        if (lcd.getTouch(&x, &y)) {
            if (esp_timer_get_time() / 1000 - last_touch > 300) {
                handleTouch(x, y);
                last_touch = esp_timer_get_time() / 1000;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
