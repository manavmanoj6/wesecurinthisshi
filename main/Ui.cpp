#include "Ui.h"
#include "Shared.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <driver/spi_master.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

// Funky Theme Colors
#define TH_BG 0x6018           // Funky Purple
#define TH_KEY 0xFB00          // Neon Orange
#define TH_KEY_DARK 0xF81F     // Hot Pink
#define TH_ACCENT 0x07FF       // Cyan
#define TH_ACCENT_GREEN 0x07E0 // Lime Green
#define TH_BAR 0x001F          // Deep Blue
#define TH_TEXT 0xFFFF         // White
#define TH_TEXT_DIM 0xFFE0     // Yellow

uint16_t getRainbowColor(int screenY) {
    if (screenY < 0) screenY = 0;
    if (screenY > 239) screenY = 239;
    int phase = (screenY * 1536) / 240;
    int h = phase / 256;
    int f = phase % 256;
    int q = 255 - f;
    int r = 0, g = 0, b = 0;
    switch(h) {
        case 0: r = 255; g = f; b = 0; break;
        case 1: r = q; g = 255; b = 0; break;
        case 2: r = 0; g = 255; b = f; break;
        case 3: r = 0; g = q; b = 255; break;
        case 4: r = f; g = 0; b = 255; break;
        case 5: r = 255; g = 0; b = q; break;
    }
    r /= 3; g /= 3; b /= 3; // Darken for background readability
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
}

template <typename T>
void drawRainbowBg(T* d, int x, int y, int w, int h, int screenY_offset) {
    for (int i = 0; i < h; i++) {
        d->drawFastHLine(x, y + i, w, getRainbowColor(screenY_offset + i));
    }
}

char logBuffer[100][80] = {0};
int logHead = 0;
int logCount = 0;
int logScrollY = 0;

char chatHistory[50][100] = {0};
bool chatIsSelf[50] = {false};
int chatCount = 0;
int chatScrollY = 0;
enum ViewMode { VIEW_CHAT, VIEW_LOG, VIEW_CONTACTS };
ViewMode currentView = VIEW_CHAT;
bool logsDirty = false;
bool isNumKeyboard = false;
int capsMode = 0; // 0=lower, 1=shift, 2=caps
vprintf_like_t orig_log_vprintf = NULL;

uint8_t contactList[30] = {0};
int numContacts = 0;

void discoveredContact(uint8_t node_id) {
  for (int i = 0; i < numContacts; i++)
    if (contactList[i] == node_id)
      return;
  if (numContacts < 30) {
    contactList[numContacts++] = node_id;
    logsDirty = true;
  }
}

int custom_log_vprintf(const char *fmt, va_list args) {
  char temp[120];
  va_list args_copy;
  va_copy(args_copy, args);
  int len = vsnprintf(temp, sizeof(temp), fmt, args_copy);
  va_end(args_copy);
  if (len > 0) {
    for (int i = 0; i < len; i++)
      if (temp[i] == '\r' || temp[i] == '\n')
        temp[i] = ' ';
    strncpy(logBuffer[logHead], temp, 79);
    logBuffer[logHead][79] = 0;
    logHead = (logHead + 1) % 100;
    if (logCount < 100) logCount++;
    logsDirty = true;
  }
  if (orig_log_vprintf)
    return orig_log_vprintf(fmt, args);
  return vprintf(fmt, args);
}

LGFX lcd;
LGFX_Sprite chatSprite(&lcd);
char inputBuf[200] = {0};
int inputLen = 0;
int chatOffsetY = 0;

void fillScreenRainbow() {
    drawRainbowBg(&lcd, 0, 0, 320, 240, 0);
}

void drawTopBar() {
  lcd.fillRect(0, 0, 320, 24, TH_BAR);
  lcd.setTextColor(TH_TEXT);
  lcd.drawString("[CHAT]", 10, 6);
  lcd.drawString("[LOG]", 100, 6);
  lcd.drawString("[PEERS]", 190, 6);
  if (currentView == VIEW_CHAT) {
    char status[32];
    snprintf(status, sizeof(status), "N%d:%s", current_target,
             peerMgr.isSecure(current_target) ? "SEC" : "UNS");
    lcd.setTextColor(
        peerMgr.isSecure(current_target) ? TFT_GREEN : 0xF800); // 0xF800 is Red
    lcd.drawString(status, 260, 6);
  }
}

LGFX::LGFX(void) {
  {
    auto cfg = _bus_instance.config();
    cfg.spi_host = HSPI_HOST; // standard HSPI
    cfg.spi_mode = 0;
    cfg.freq_write = 40000000;
    cfg.freq_read = 16000000;
    cfg.spi_3wire = false;
    cfg.use_lock = true;
    cfg.dma_channel = SPI_DMA_CH_AUTO;
    cfg.pin_sclk = 18;
    cfg.pin_mosi = 23;
    cfg.pin_miso = 19;
    cfg.pin_dc = 2;
    _bus_instance.config(cfg);
    _panel_instance.setBus(&_bus_instance);
  }
  {
    auto cfg = _panel_instance.config();
    cfg.pin_cs = 5;
    cfg.pin_rst = 4;
    cfg.pin_busy = -1;
    cfg.memory_width = 240;
    cfg.memory_height = 320;
    cfg.panel_width = 240;
    cfg.panel_height = 320;
    cfg.offset_x = 0;
    cfg.offset_y = 0;
    cfg.offset_rotation = 0;
    cfg.dummy_read_pixel = 8;
    cfg.dummy_read_bits = 1;
    cfg.readable = true;
    cfg.invert = false; // Swapped to false to fix pure white background error
    cfg.rgb_order = false;
    cfg.dlen_16bit = false;
    cfg.bus_shared = true;
    _panel_instance.config(cfg);
  }
  {
    auto cfg = _touch_instance.config();
    // Expanded boundaries for absolute edge-to-edge linearity
    cfg.x_min = 3850;
    cfg.x_max = 150;
    cfg.y_min = 150;
    cfg.y_max = 3850;
    cfg.pin_int = -1;
    cfg.bus_shared = true;
    cfg.offset_rotation = 0;
    cfg.spi_host = HSPI_HOST;
    cfg.freq = 1000000;
    cfg.pin_sclk = 18;
    cfg.pin_mosi = 23;
    cfg.pin_miso = 19;
    cfg.pin_cs = 14; // User requested Touch CS on 14
    _touch_instance.config(cfg);
    _panel_instance.setTouch(&_touch_instance);
  }
  setPanel(&_panel_instance);
}

void drawKeyboard() {
  drawRainbowBg(&lcd, 0, 124, 320, 116, 124);
  const char *rowsAlphaUpper[3] = {"QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"};
  const char *rowsAlphaLower[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
  const char *rowsNum[3] = {"1234567890", "@#%&*-+()!", ".,:;'\"/?"};
  const char **rows = isNumKeyboard
                          ? rowsNum
                          : ((capsMode > 0) ? rowsAlphaUpper : rowsAlphaLower);
  int yOff = 124;
  for (int r = 0; r < 3; r++) {
    int keys = strlen(rows[r]);
    int kw = 320 / keys;
    for (int c = 0; c < keys; c++) {
      int x = c * kw;
      int y = yOff + (r * 29);
      lcd.fillRoundRect(x + 1, y + 1, kw - 2, 27, 4, TH_KEY);
      lcd.setCursor(x + kw / 2 - 4, y + 6);
      lcd.setTextColor(TH_TEXT);
      lcd.printf("%c", rows[r][c]);
    }
  }
  int bW = 64; // 320 / 5
  int bY = yOff + 87; // 3 * 29
  lcd.fillRoundRect(1, bY + 1, bW - 2, 27, 4, TH_KEY_DARK);
  lcd.setTextColor(TH_TEXT);
  lcd.drawString(isNumKeyboard ? "ABC" : "123", 22, bY + 8);

  lcd.fillRoundRect(bW + 1, bY + 1, bW - 2, 27, 4,
                    capsMode > 0 ? TH_ACCENT : TH_KEY_DARK);
  const char *shfLbl =
      (capsMode == 0) ? "shf" : ((capsMode == 1) ? "SHF" : "CAP");
  if (!isNumKeyboard)
    lcd.drawString(shfLbl, bW + 20, bY + 8);

  lcd.fillRoundRect(bW * 2 + 1, bY + 1, bW - 2, 27, 4, TH_KEY);
  lcd.drawString("SPC", bW * 2 + 20, bY + 8);

  lcd.fillRoundRect(bW * 3 + 1, bY + 1, bW - 2, 27, 4, TH_KEY_DARK);
  lcd.drawString("DEL", bW * 3 + 20, bY + 8);

  lcd.fillRoundRect(bW * 4 + 1, bY + 1, bW - 2, 27, 4, TH_ACCENT_GREEN);
  lcd.drawString("SND", bW * 4 + 20, bY + 8);
}

void addMessage(const char *msg, bool isSelf) {
  if (chatCount < 50) {
    strncpy(chatHistory[chatCount], msg, 99);
    chatIsSelf[chatCount] = isSelf;
    chatCount++;
  } else {
    for (int i = 0; i < 49; i++) {
        strcpy(chatHistory[i], chatHistory[i+1]);
        chatIsSelf[i] = chatIsSelf[i+1];
    }
    strncpy(chatHistory[49], msg, 99);
    chatIsSelf[49] = isSelf;
  }
  chatScrollY = 0;
  logsDirty = true;
}

void drawChatMessages() {
  drawRainbowBg(&chatSprite, 0, 0, 320, 80, 24);
  int drawY = 80 - 22 + chatScrollY; 
  for(int i = chatCount -1; i >= 0; i--) {
    if (drawY + 22 < 0) break;
    if (drawY >= 80) { drawY -= 22; continue; }
    
    int len = strlen(chatHistory[i]);
    int tw = (len * 6) + 12;
    if (tw > 300) tw = 300;
    
    if (chatIsSelf[i]) {
      chatSprite.fillRoundRect(316 - tw, drawY, tw, 18, 5, TH_ACCENT);
      chatSprite.setTextColor(TH_TEXT);
      chatSprite.setCursor(316 - tw + 6, drawY + 5);
      chatSprite.printf("%s", chatHistory[i]);
    } else {
      chatSprite.fillRoundRect(4, drawY, tw, 18, 5, TH_KEY_DARK);
      chatSprite.setTextColor(TH_TEXT);
      chatSprite.setCursor(10, drawY + 5);
      chatSprite.printf("%s", chatHistory[i]);
    }
    drawY -= 22;
  }
  chatSprite.pushSprite(0, 24);
}

void drawLogs() {
  drawRainbowBg(&lcd, 0, 24, 320, 216, 24);
  lcd.setTextColor(TFT_GREEN);
  
  int maxLog = (logCount < 100) ? logCount : 100;
  int drawY = 216 - 14 + logScrollY;
  
  lcd.startWrite();
  for (int i = 0; i < maxLog; i++) {
    if (drawY + 14 <= 24) break;
    
    int idx = (logHead - 1 - i + 100) % 100;
    if (drawY < 240) {
      lcd.drawString(logBuffer[idx], 5, drawY);
    }
    drawY -= 14;
  }
  lcd.endWrite();
}

void handleTouch(int x, int y) {
  if (y < 24) {
    if (x < 100)
      currentView = VIEW_CHAT;
    else if (x < 190)
      currentView = VIEW_LOG;
    else if (x < 320)
      currentView = VIEW_CONTACTS;

    if (currentView == VIEW_LOG || currentView == VIEW_CONTACTS) {
      fillScreenRainbow();
      drawTopBar();
      logsDirty = true;
    } else {
      fillScreenRainbow();
      drawTopBar();

      drawKeyboard();
      lcd.fillRect(0, 104, 320, 20, TH_BAR);
      lcd.fillRoundRect(4, 106, 312, 16, 8, TH_KEY_DARK);
      lcd.setTextColor(TH_TEXT);
      lcd.drawString(inputBuf, 10, 110);
      logsDirty = true;
    }
    return;
  }

  if (currentView == VIEW_CONTACTS) {
    int drawY = 30;
    for (int i = 0; i < numContacts; i++) {
      if (drawY > 180)
        break;
      if (y > drawY && y < drawY + 20) {
        if (x > 260) {
          if (current_target >= 200 && current_target <= 250 && peerMgr.isSecure(contactList[i])) {
            char cmd[200] = {0};
            snprintf(cmd, sizeof(cmd), "add %d %d", current_target, contactList[i]);
            extern QueueHandle_t tx_queue;
            xQueueSend(tx_queue, cmd, 0);
            vTaskDelay(pdMS_TO_TICKS(50));
            logsDirty = true;
          }
          return;
        } else {
          current_target = contactList[i];
          currentView = VIEW_CHAT;
          fillScreenRainbow();
          drawTopBar();
          drawKeyboard();
          lcd.fillRect(0, 139, 240, 26, TH_BAR);
          lcd.fillRoundRect(4, 141, 232, 22, 11, TH_KEY_DARK);
          lcd.setTextColor(TH_TEXT);
          lcd.drawString(inputBuf, 10, 146);
          logsDirty = true;
          return;
        }
      }
      drawY += 24;
    }
    
    for (int i = 0; i < 5; i++) {
      if (peerMgr.groups[i].active) {
        if (drawY > 180) break;
        if (y > drawY && y < drawY + 20) {
          current_target = peerMgr.groups[i].id;
          currentView = VIEW_CHAT;
          fillScreenRainbow();
          drawTopBar();
          drawKeyboard();
          lcd.fillRect(0, 139, 240, 26, TH_BAR);
          lcd.fillRoundRect(4, 141, 232, 22, 11, TH_KEY_DARK);
          lcd.setTextColor(TH_TEXT);
          lcd.drawString(inputBuf, 10, 146);
          logsDirty = true;
          return;
        }
        drawY += 24;
      }
    }

    if (y > 200) {
      if (x < 120) {
        extern QueueHandle_t tx_queue;
        char cmd[200] = {0};
        strcpy(cmd, "/ping");
        xQueueSend(tx_queue, cmd, 0);
        lcd.fillRoundRect(10, 200, 140, 30, 8, TH_KEY_DARK);
      } else {
        extern QueueHandle_t tx_queue;
        int nextId = 200;
        for (int i = 200; i <= 250; i++) {
          bool exists = false;
          for (int j = 0; j < 5; j++) {
            if (peerMgr.groups[j].active && peerMgr.groups[j].id == i) {
              exists = true; break;
            }
          }
          if (!exists) { nextId = i; break; }
        }
        char cmd[200] = {0};
        snprintf(cmd, sizeof(cmd), "mkgroup %d", nextId);
        xQueueSend(tx_queue, cmd, 0);
        lcd.fillRoundRect(160, 200, 140, 30, 8, TH_KEY_DARK);
      }
      vTaskDelay(pdMS_TO_TICKS(50));
      logsDirty = true;
    }
    return;
  }

  if (currentView == VIEW_LOG)
    return;

  if (y < 124)
    return;
  int yOff = 124;
  char pressed = 0;
  const char *rowsAlphaUpper[3] = {"QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"};
  const char *rowsAlphaLower[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
  const char *rowsNum[3] = {"1234567890", "@#%&*-+()!", ".,:;'\"/?"};
  const char **rows = isNumKeyboard
                          ? rowsNum
                          : ((capsMode > 0) ? rowsAlphaUpper : rowsAlphaLower);

  if (y > yOff && y < yOff + 29) {
    int keys = strlen(rows[0]);
    int kw = 320 / keys;
    pressed = rows[0][x / kw];
  } else if (y > yOff + 29 && y < yOff + 58) {
    int keys = strlen(rows[1]);
    int kw = 320 / keys;
    pressed = rows[1][x / kw];
  } else if (y > yOff + 58 && y < yOff + 87) {
    int keys = strlen(rows[2]);
    if (x < 320 / keys * keys) {
      int kw = 320 / keys;
      pressed = rows[2][x / kw];
    }
  } else if (y > yOff + 87) {
    int bW = 48;
    if (x < bW) {
      isNumKeyboard = !isNumKeyboard;
      drawKeyboard();
      return;
    } else if (x < bW * 2) {
      if (!isNumKeyboard) {
        capsMode = (capsMode + 1) % 3;
        drawKeyboard();
      }
      return;
    } else if (x < bW * 3) {
      pressed = ' ';
    } else if (x < bW * 4) {
      pressed = '\b';
    } else {
      pressed = '\r';
    }
  }

  if (pressed == '\b' && inputLen > 0) {
    inputBuf[--inputLen] = 0;
  } else if (pressed == '\r' && inputLen > 0) {
    if (strcmp(inputBuf, "reset") == 0 || strncmp(inputBuf, "setid ", 6) == 0 ||
        strncmp(inputBuf, "mkgroup ", 8) == 0 ||
        strncmp(inputBuf, "add ", 4) == 0 || strncmp(inputBuf, "to ", 3) == 0 ||
        strcmp(inputBuf, "init") == 0) {
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
    if (capsMode == 1 &&
        !isNumKeyboard) { // Revert to lowercase after single Shift
      capsMode = 0;
      drawKeyboard();
    }
  }

  lcd.fillRect(0, 104, 320, 20, TH_BAR);
  lcd.fillRoundRect(4, 106, 312, 16, 8, TH_KEY_DARK);
  lcd.setTextColor(TH_TEXT);
  lcd.drawString(inputBuf, 10, 110);

  // Visual feedback for touch
  lcd.fillCircle(x, y, 8, TH_ACCENT);
  vTaskDelay(pdMS_TO_TICKS(40));
  drawKeyboard(); // redraw fully to cleanly erase footprint
  // redraw input bar
  lcd.fillRect(0, 104, 320, 20, TH_BAR);
  lcd.fillRoundRect(4, 106, 312, 16, 8, TH_KEY_DARK);
  lcd.setTextColor(TH_TEXT);
  lcd.drawString(inputBuf, 10, 110);
}

void ui_init() {
  orig_log_vprintf = esp_log_set_vprintf(custom_log_vprintf);

  lcd.init();
  lcd.setRotation(1);
  fillScreenRainbow();

  // Top Bar
  drawTopBar();

  chatSprite.createSprite(320, 80);
  addMessage("Connected safely.", false);
  drawChatMessages();

  drawKeyboard();
  lcd.fillRect(0, 139, 240, 26, TH_BAR);
  lcd.fillRoundRect(4, 141, 232, 22, 11, TH_KEY_DARK);
}

void ui_task(void *arg) {
  ui_init();
  uint16_t x, y;
  int64_t last_touch = 0;
  int64_t last_status_upd = 0;
  while (1) {
    if (esp_timer_get_time() / 1000 - last_status_upd > 1000) {
      if (currentView == VIEW_CHAT) {
        char status[32];
        snprintf(status, sizeof(status), "N%d:%s", current_target,
                 peerMgr.isSecure(current_target) ? "SEC" : "UNS");
        lcd.fillRect(250, 0, 70, 24, TH_BAR); // Fast clear right edge
        lcd.setTextColor(peerMgr.isSecure(current_target) ? TFT_GREEN : 0xF800);
        lcd.drawString(status, 260, 6);
      }
      last_status_upd = esp_timer_get_time() / 1000;
    }

    if (logsDirty) {
      if (currentView == VIEW_LOG) {
        drawLogs();
        logsDirty = false;
      } else if (currentView == VIEW_CHAT) {
        drawChatMessages();
        logsDirty = false;
      } else if (currentView == VIEW_CONTACTS) {
        drawRainbowBg(&lcd, 0, 24, 320, 216, 24);
        lcd.setTextColor(TH_TEXT);
        int drawY = 30;
        for (int i = 0; i < numContacts; i++) {
          if (drawY > 180)
            break;
          uint16_t cardColor =
              (contactList[i] == current_target) ? TH_ACCENT : TH_KEY_DARK;
          lcd.fillRoundRect(10, drawY, 240, 20, 5, cardColor);
          char tmp[30];
          snprintf(tmp, sizeof(tmp), "Node %d", contactList[i]);
          lcd.drawString(tmp, 20, drawY + 6);
          
          if (current_target >= 200 && current_target <= 250) {
            if (peerMgr.isSecure(contactList[i])) {
              lcd.fillRoundRect(260, drawY, 40, 20, 5, TH_ACCENT_GREEN);
              lcd.setTextColor(TH_TEXT);
              lcd.drawString("[+]", 270, drawY + 6);
              lcd.setTextColor(TH_TEXT);
            }
          }
          drawY += 24;
        }

        for (int i = 0; i < 5; i++) {
          if (peerMgr.groups[i].active) {
            if (drawY > 180) break;
            uint16_t cardColor = (peerMgr.groups[i].id == current_target) ? TH_ACCENT : TH_KEY_DARK;
            lcd.fillRoundRect(10, drawY, 300, 20, 5, cardColor);
            char tmp[30];
            snprintf(tmp, sizeof(tmp), "Group %d (%d)", peerMgr.groups[i].id, peerMgr.groups[i].count);
            lcd.drawString(tmp, 20, drawY + 6);
            drawY += 24;
          }
        }

        lcd.fillRoundRect(10, 200, 140, 30, 8, TH_ACCENT_GREEN);
        lcd.drawString("PING ALL", 45, 209);
        lcd.fillRoundRect(160, 200, 140, 30, 8, TH_ACCENT);
        lcd.drawString("NEW GRP", 195, 209);
        logsDirty = false;
      }
    }

    static int touchStartX = -1, touchStartY = -1, lastTouchY = -1;
    static bool isDragging = false;
    static int64_t drag_time = 0;

    if (lcd.getTouch(&x, &y)) {
      if (touchStartY == -1) {
        touchStartX = x;
        touchStartY = y;
        lastTouchY = y;
        isDragging = false;
      } else {
        int dy = y - lastTouchY;
        if (abs(y - touchStartY) > 5) {
          isDragging = true;
          if (currentView == VIEW_LOG) {
            logScrollY += dy;
            if (logScrollY < 0) logScrollY = 0;
            int maxScr = (logCount * 14) - 216 + 14;
            if (maxScr < 0) maxScr = 0;
            if (logScrollY > maxScr) logScrollY = maxScr;
            logsDirty = true;
          } else if (currentView == VIEW_CHAT && y < 104) {
            chatScrollY += dy;
            if (chatScrollY < 0) chatScrollY = 0;
            int maxScr = (chatCount * 22) - 80;
            if (maxScr < 0) maxScr = 0;
            if (chatScrollY > maxScr) chatScrollY = maxScr;
            logsDirty = true;
          }
        }
        lastTouchY = y;
      }
      last_touch = esp_timer_get_time() / 1000;
    } else {
      if (touchStartY != -1) {
        if (!isDragging && (esp_timer_get_time() / 1000 - drag_time > 300)) {
          handleTouch(touchStartX, touchStartY);
          drag_time = esp_timer_get_time() / 1000;
        }
        touchStartY = -1;
        isDragging = false;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}
