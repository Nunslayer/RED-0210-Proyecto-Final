// ESP32 – WiFi Scanner + Control de Acceso (Blanca/Negra/En Espera) con Web UI
// - AP: SSID "ESP32_GRUPO6_TI", pass "12345678"    (http://192.168.4.1)
// - Página "/"  : Escáner de redes con barras (refresca cada 2 s). Escanea cada 12 s).
// - Página "/admin?pass=admin1234": Panel para listas Blanca/Negra, "En espera", Log de Eventos y herramientas avanzadas.
// - Gating: Todos los dispositivos nuevos (salvo la MAC pre-aprobada) se envían a "En espera".
// - Persistencia en NVS (Preferences): allow (blanca), black (negra), alias por MAC.
// - Tu laptop está preagregada a la LISTA BLANCA (cambia MY_LAPTOP_MAC si hace falta).
// - Nombres/Alias para las MAC.
//
// Autor: Grupo 6 (Ketfer G)
// Modificado para un look profesional y funcionalidades empresariales por Gemini 🚀

#include <WiFi.h>
#include <esp_wifi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <DNSServer.h>
#include "FS.h"
#include "LittleFS.h"

// ===== CONFIG AP / ADMIN =====
#define DEFAULT_AP_SSID            "ESP32_GRUPO6_TI"
#define DEFAULT_AP_PASS            "12345678"
#define ADMIN_PASSWORD     "admin1234"

// ===== SCANNER =====
const unsigned long SCAN_INTERVAL_MS = 12000; // 12 s
unsigned long lastScan = 0;

struct NetRes {
  String ssid;
  String bssid;
  int rssi;
  int ch;
  wifi_auth_mode_t enc;
};
static const int MAX_NETS = 60;
NetRes nets[MAX_NETS];
int netCount = 0;

// ===== CONTROL DE ACCESO =====
Preferences prefs;
WebServer server(80);
DNSServer dnsServer;

static const int MAX_MACS        = 120;  // por lista (allow/black)
static const int MAX_CONNECTED   = 32;
static const int MAX_PENDING     = 128;
static const uint32_t PENDING_TTL_MS = 5UL * 60UL * 1000UL; // 5 min

// ⚠ Cambia esta MAC por la de tu laptop:
const char* MY_LAPTOP_MAC = "D0:39:57-E4-FB-65"; 

struct Device {
  String mac;
  String alias; // Campo de alias
  uint32_t lastSeenMs;
  uint16_t aid;
  int8_t rssi;
};
String allowList[MAX_MACS]; int allowCount = 0;
String blackList[MAX_MACS]; int blackCount = 0;
bool filteringEnabled = true;

Device connected[MAX_CONNECTED]; int connectedCount = 0;
Device pending[MAX_PENDING];       int pendingCount     = 0;

// Almacenamiento de alias
Preferences aliasPrefs;

// Almacenamiento de configuracion AP
Preferences apConfig;
String ap_ssid = DEFAULT_AP_SSID;
String ap_pass = DEFAULT_AP_PASS;

// ===== Log de eventos =====
struct LogEvent {
  uint32_t timestamp;
  String message;
};
const int MAX_LOG_EVENTS = 50;
LogEvent eventLog[MAX_LOG_EVENTS];
int logCount = 0;

void logEvent(const String& message) {
  if (logCount < MAX_LOG_EVENTS) {
    eventLog[logCount].timestamp = millis();
    eventLog[logCount].message = message;
    logCount++;
  } else {
    for (int i = 0; i < MAX_LOG_EVENTS - 1; ++i) {
      eventLog[i] = eventLog[i + 1];
    }
    eventLog[MAX_LOG_EVENTS - 1].timestamp = millis();
    eventLog[MAX_LOG_EVENTS - 1].message = message;
  }
}

// ====== Utils comunes ======
String macToStr(const uint8_t* bssid){
  char buf[18];
  snprintf(buf,sizeof(buf),"%02X:%02X:%02X:%02X:%02X:%02X",
    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
  return String(buf);
}
bool isHexDigit(char c){ return (c>='0'&&c<='9')||(c>='A'&&c<='F'); }
String toUpperNoSpaces(const String& s){
  String r; r.reserve(s.length());
  for(char c: s) if(c!=' '&&c!='\t'&&c!='\r'&&c!='\n') r += (char)toupper((unsigned char)c);
  return r;
}
bool normalizeMac(String in, String &out){
  String s = toUpperNoSpaces(in);
  String hex; hex.reserve(12);
  for (char c: s) if (isHexDigit(c)) hex += c;
  if (hex.length()!=12) return false;
  out = "";
  for (int i=0;i<12;i+=2){ if(i) out += ":"; out += hex.substring(i,i+2); }
  return true;
}
String jsonEscape(const String& in){
  String o; o.reserve(in.length()+4);
  for (size_t i=0;i<in.length();++i){
    char c = in[i];
    if (c=='\\' || c=='"') { o += '\\'; o += c; }
    else if ((unsigned char)c < 0x20) { o += ' '; }
    else { o += c; }
  }
  return o;
}
String timeAgo(uint32_t ms) {
    uint32_t seconds = ms / 1000;
    if (seconds < 60) {
        return String(seconds) + "s";
    } else if (seconds < 3600) {
        return String(seconds / 60) + "m";
    } else if (seconds < 86400) {
        return String(seconds / 3600) + "h";
    } else {
        return String(seconds / 86400) + "d";
    }
}

// ====== Scanner helpers ======
int qualityFromRSSI(int rssi){
  if (rssi <= -100) return 0;
  if (rssi >= -50)  return 100;
  return 2 * (rssi + 100);
}
String encTypeToStr(wifi_auth_mode_t e){
  switch(e){
    case WIFI_AUTH_OPEN:              return "Abierta";
    case WIFI_AUTH_WEP:                return "WEP";
    case WIFI_AUTH_WPA_PSK:            return "WPA";
    case WIFI_AUTH_WPA2_PSK:           return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:       return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE:    return "WPA2-E";
#if defined(WIFI_AUTH_WPA3_PSK)
    case WIFI_AUTH_WPA3_PSK:           return "WPA3";
#endif
#if defined(WIFI_AUTH_WPA2_WPA3_PSK)
    case WIFI_AUTH_WPA2_WPA3_PSK:      return "WPA2/WPA3";
#endif
    default:                           return "Desconocida";
  }
}

// ====== Scanner core ======
void runScan(){
  int n = WiFi.scanNetworks(false, true); // sync + hidden
  netCount = 0;
  if (n <= 0){ WiFi.scanDelete(); return; }

  int* idx = (int*)malloc(n*sizeof(int));
  for (int i=0;i<n;i++) idx[i]=i;
  for (int a=0;a<n-1;a++){
    for (int b=a+1;b<n;b++){
      if (WiFi.RSSI(idx[b]) > WiFi.RSSI(idx[a])){
        int t=idx[a]; idx[a]=idx[b]; idx[b]=t;
      }
    }
  }
  int take = (n < MAX_NETS ? n : MAX_NETS);
  for (int k=0;k<take;k++){
    int i = idx[k];
    nets[k].ssid = WiFi.SSID(i);
    if (nets[k].ssid.length()==0) nets[k].ssid = "<oculta>";
    nets[k].bssid = macToStr(WiFi.BSSID(i));
    nets[k].rssi  = WiFi.RSSI(i);
    nets[k].ch    = WiFi.channel(i);
    nets[k].enc   = WiFi.encryptionType(i);
  }
  netCount = take;
  free(idx);
  WiFi.scanDelete();
}

// ====== Listas (NVS) ======
bool macInList(const String& mac, String* list, int count){
  for(int i=0;i<count;i++) if (list[i]==mac) return true;
  return false;
}
bool macAllowed(const String& mac){ return macInList(mac, allowList, allowCount); }
bool macBlocked(const String& mac){ return macInList(mac, blackList, blackCount); }
bool addToList(const String& mac, String* list, int &count){
  if (count>=MAX_MACS) return false;
  if (macInList(mac, list, count)) return true;
  list[count++] = mac;
  return true;
}
bool delFromList(const String& mac, String* list, int &count){
  for (int i=0;i<count;i++){
    if (list[i]==mac){
      for (int j=i+1;j<count;j++) list[j-1]=list[j];
      count--; return true;
    }
  }
  return false;
}
bool addMacAllow(const String& mac){ return addToList(mac, allowList, allowCount); }
bool delMacAllow(const String& mac){ return delFromList(mac, allowList, allowCount); }
bool addMacBlack(const String& mac){ return addToList(mac, blackList, blackCount); }
bool delMacBlack(const String& mac){ return delFromList(mac, blackList, blackCount); }

String serializeList(String* list, int count){
  String csv;
  for (int i=0;i<count;i++){ if(i) csv+=','; csv+=list[i]; }
  return csv;
}
void deserializeList(const String& csv, String* list, int &count){
  count=0;
  int start=0;
  while (start < (int)csv.length()){
    int idx = csv.indexOf(',', start);
    String item = (idx==-1)? csv.substring(start) : csv.substring(start,idx);
    item.trim();
    if (item.length() && count<MAX_MACS) list[count++]=item;
    if (idx==-1) break; start = idx+1;
  }
}
void loadListsFromNVS(){
  prefs.begin("maclist", true);
  String csvA = prefs.getString("allow", "");
  String csvB = prefs.getString("black", "");
  prefs.end();
  deserializeList(csvA, allowList, allowCount);
  deserializeList(csvB, blackList, blackCount);
}
void saveAllowToNVS(){
  String csv = serializeList(allowList, allowCount);
  prefs.begin("maclist", false);
  prefs.putString("allow", csv);
  prefs.end();
}
void saveBlackToNVS(){
  String csv = serializeList(blackList, blackCount);
  prefs.begin("maclist", false);
  prefs.putString("black", csv);
  prefs.end();
}

void saveAliasToNVS(const String& mac, const String& alias){
  aliasPrefs.begin("mac_alias", false);
  aliasPrefs.putString(mac.c_str(), alias);
  aliasPrefs.end();
}

String getAliasFromNVS(const String& mac){
  aliasPrefs.begin("mac_alias", true);
  String alias = aliasPrefs.getString(mac.c_str(), "");
  aliasPrefs.end();
  return alias;
}

void deleteAliasFromNVS(const String& mac){
  aliasPrefs.begin("mac_alias", false);
  aliasPrefs.remove(mac.c_str());
  aliasPrefs.end();
}

void loadAPConfigFromNVS() {
  apConfig.begin("ap_config", true);
  ap_ssid = apConfig.getString("ssid", DEFAULT_AP_SSID);
  ap_pass = apConfig.getString("pass", DEFAULT_AP_PASS);
  apConfig.end();
}

void saveAPConfigToNVS(const String& ssid, const String& pass) {
  apConfig.begin("ap_config", false);
  apConfig.putString("ssid", ssid);
  apConfig.putString("pass", pass);
  apConfig.end();
}

// ====== Conectados/Pendientes ======
int findConnectedIdx(const String& mac){
  for(int i=0;i<connectedCount;i++) if (connected[i].mac==mac) return i;
  return -1;
}
void addOrUpdateConnected(const String& mac, uint16_t aid){
  int idx = findConnectedIdx(mac);
  if (idx>=0){ connected[idx].lastSeenMs = millis(); connected[idx].aid = aid; return; }
  if (connectedCount<MAX_CONNECTED){
    connected[connectedCount++] = {mac, getAliasFromNVS(mac), millis(), aid, 0};
  }
}
void removeConnected(const String& mac){
  int idx = findConnectedIdx(mac);
  if (idx<0) return;
  for (int j=idx+1;j<connectedCount;j++) connected[j-1]=connected[j];
  connectedCount--;
}
int findPendingIdx(const String& mac){
  for(int i=0;i<pendingCount;i++) if (pending[i].mac==mac) return i;
  return -1;
}
bool isNewPending = false;
void addOrUpdatePending(const String& mac, uint16_t aid){
  int idx = findPendingIdx(mac);
  if (idx>=0){ pending[idx].lastSeenMs = millis(); pending[idx].aid = aid; return; }
  
  // Set flag for new pending device
  isNewPending = true;

  if (pendingCount<MAX_PENDING){
    pending[pendingCount++] = {mac, getAliasFromNVS(mac), millis(), aid, 0};
  } else {
    int oldest=0; uint32_t t=pending[0].lastSeenMs;
    for(int i=1;i<pendingCount;i++) if (pending[i].lastSeenMs<t){ oldest=i; t=pending[i].lastSeenMs; }
    pending[oldest] = {mac, getAliasFromNVS(mac), millis(), aid, 0};
  }
}
void prunePending(){
  uint32_t now = millis();
  int w=0;
  for (int i=0;i<pendingCount;i++){
    if (now - pending[i].lastSeenMs <= PENDING_TTL_MS){
      if (w!=i) pending[w]=pending[i];
      w++;
    }
  }
  pendingCount = w;
}
void refreshRSSIConnected(){
  wifi_sta_list_t sta_list;
  if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK) return;
  for (int i=0;i<connectedCount;i++) connected[i].rssi = 0;
  for (int i=0;i<sta_list.num; i++){
    const wifi_sta_info_t &st = sta_list.sta[i];
    String m = macToStr(st.mac);
    int idx = findConnectedIdx(m);
    if (idx >= 0) connected[idx].rssi = st.rssi;
  }
}

// ====== Eventos WiFi (gating) ======
void WiFiEventHandler(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
    const wifi_event_ap_staconnected_t &conn = info.wifi_ap_staconnected;
    String m = macToStr(conn.mac);
    
    if (macAllowed(m)) {
        logEvent("MAC " + m + " se ha conectado.");
        addOrUpdateConnected(m, conn.aid);
    }
    else {
        logEvent("Nuevo dispositivo " + m + " intentó conectarse y fue enviado a la lista de espera.");
        addOrUpdatePending(m, conn.aid);
        esp_wifi_deauth_sta(conn.aid);
    }
  }
  else if (event == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
    const wifi_event_ap_stadisconnected_t &disc = info.wifi_ap_stadisconnected;
    String m = macToStr(disc.mac);
    logEvent("MAC " + m + " se ha desconectado.");
    removeConnected(m);
  }
}

// ====== AUTH admin ======
bool isAuthed(){ return server.hasArg("pass") && server.arg("pass")==ADMIN_PASSWORD; }
bool guard(){ if(!isAuthed()){ server.send(403,"text/plain","Forbidden"); return true; } return false; }

// ====== API Scanner ======
void handleApiScan(){
  String j; j.reserve(8192);
  j += "[";
  for (int i=0;i<netCount;i++){
    if (i) j += ",";
    j += "{\"ssid\":\"";
    String s = nets[i].ssid; s.replace("\\","\\\\"); s.replace("\"","\\\"");
    j += s; j += "\",\"bssid\":\""; j += nets[i].bssid;
    j += "\",\"rssi\":";
    j += String(nets[i].rssi);
    j += ",\"quality\":";
    j += String(qualityFromRSSI(nets[i].rssi));
    j += ",\"channel\":";
    j += String(nets[i].ch);
    j += ",\"security\":\"";
    j += encTypeToStr(nets[i].enc);
    j += "\"}";
  }
  j += "]";
  server.send(200, "application/json", j);
}

// ====== API Admin (JSON de estado + acciones) ======
void handleApiState(){
  if (guard()) return;
  prunePending();

  String j; j.reserve(12000);
  j += "{\"ap_ssid\":\""; j += jsonEscape(ap_ssid);
  j += "\",\"ap_pass\":\""; j += jsonEscape(ap_pass);
  j += "\",\"filtering\":"; j += (filteringEnabled? "true":"false");
  j += ",\"allowed\":[";
  for (int i=0;i<allowCount;i++){ 
    if(i) j+=','; 
    j += "{\"mac\":\""; j += allowList[i];
    j += "\",\"alias\":\""; j += jsonEscape(getAliasFromNVS(allowList[i])); j += "\"}";
  }
  j += "],\"black\":[";
  for (int i=0;i<blackCount;i++){ 
    if(i) j+=','; 
    j += "{\"mac\":\""; j += blackList[i];
    j += "\",\"alias\":\""; j += jsonEscape(getAliasFromNVS(blackList[i])); j += "\"}";
  }
  j += "],\"connected\":[";
  uint32_t now = millis();
  for (int i=0;i<connectedCount;i++){
    if(i) j+=',';
    j += "{\"mac\":\""; j+=connected[i].mac; 
    j += "\",\"alias\":\""; j += jsonEscape(connected[i].alias);
    j += "\",\"seen_ms\":"; j += String(now - connected[i].lastSeenMs);
    j += ",\"aid\":"; j += String(connected[i].aid);
    j += ",\"rssi\":"; j += String((int)connected[i].rssi);
    j += "}";
  }
  j += "],\"pending\":[";
  for (int i=0;i<pendingCount;i++){
    if(i) j+=',';
    j += "{\"mac\":\""; j+=pending[i].mac; 
    j += "\",\"alias\":\""; j += jsonEscape(pending[i].alias);
    j += ",\"seen_ms\":"; j += String(now - pending[i].lastSeenMs);
    j += ",\"aid\":"; j += String(pending[i].aid); j += "}";
  }
  j += "],\"newPending\":"; j += (isNewPending ? "true" : "false");
  j += "}";
  server.send(200, "application/json", j);
  isNewPending = false; // Reset flag after sending
}

void handleApiLog() {
  if (guard()) return;
  String j;
  j += "[";
  uint32_t now = millis();
  for (int i = 0; i < logCount; ++i) {
    if (i) j += ",";
    j += "{\"time\":\"";
    j += timeAgo(now - eventLog[i].timestamp);
    j += "\",\"message\":\"";
    j += jsonEscape(eventLog[i].message);
    j += "\"}";
  }
  j += "]";
  server.send(200, "application/json", j);
}

void handleDeauth(){
  if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }

  int idx = findConnectedIdx(n);
  if (idx >= 0) {
    esp_wifi_deauth_sta(connected[idx].aid);
    logEvent("Se ha desautenticado a " + n + " de la red.");
    server.send(200, "text/plain", "OK");
  } else {
    server.send(404, "text/plain", "Cliente no encontrado");
  }
}

void handleEvilTwin() {
  if (guard()) return;
  if (!server.hasArg("ssid") || !server.hasArg("pass")){
    server.send(400,"text/plain","Falta SSID o pass"); return;
  }
  
  String ssid = server.arg("ssid");
  String pass = server.arg("pass");
  
  WiFi.softAP(ssid.c_str(), pass.c_str());
  logEvent("Evil Twin activado con SSID '" + ssid + "' y pass '" + pass + "'.");
  server.send(200, "text/plain", "Evil Twin iniciado");
}

void handleStopEvilTwin(){
  if(guard()) return;
  WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str());
  logEvent("Evil Twin detenido. Volviendo a la red principal.");
  server.send(200, "text/plain", "Evil Twin detenido");
}

void handleStartSniffer() {
  if (guard()) return;
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(true);
  logEvent("Modo sniffer activado. Chequee el Monitor Serial.");
  server.send(200, "text/plain", "Modo sniffer activado");
}

void handleStopSniffer() {
  if (guard()) return;
  esp_wifi_set_promiscuous(false);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str());
  logEvent("Modo sniffer desactivado. Volviendo a modo AP.");
  server.send(200, "text/plain", "Modo sniffer desactivado");
}

void handleAddAlias(){
  if(guard()) return;
  if (!server.hasArg("mac") || !server.hasArg("alias")){ server.send(400,"text/plain","Faltan mac o alias"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  saveAliasToNVS(n, server.arg("alias"));
  logEvent("Se ha cambiado el alias para " + n + ".");
  server.send(200, "text/plain", "OK");
}

void handleAddAllow(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  if (addMacAllow(n)){ 
    saveAllowToNVS(); 
    logEvent("Se ha agregado " + n + " a la lista blanca.");
    server.send(200,"text/plain","OK"); 
  } else server.send(409,"text/plain","No agregado");
}
void handleDelAllow(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  if (delMacAllow(n)){ 
    saveAllowToNVS(); 
    deleteAliasFromNVS(n);
    logEvent("Se ha eliminado " + n + " de la lista blanca.");
    server.send(200,"text/plain","OK"); 
  } else server.send(404,"text/plain","No encontrado");
}
void handleApprove(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  if (addMacAllow(n)) saveAllowToNVS();
  int idx=findPendingIdx(n); if(idx>=0){ for(int j=idx+1;j<pendingCount;j++) pending[j-1]=pending[j]; pendingCount--; }
  logEvent("Se ha aprobado " + n + " y se agregó a la lista blanca.");
  server.send(200,"text/plain","OK");
}
void handleAddBlack(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  if (addMacBlack(n)){ 
    saveBlackToNVS(); 
    logEvent("Se ha agregado " + n + " a la lista negra.");
    server.send(200,"text/plain","OK"); 
  } else server.send(409,"text/plain","No agregado");
}
void handleDelBlack(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  if (delMacBlack(n)){ 
    saveBlackToNVS(); 
    deleteAliasFromNVS(n);
    logEvent("Se ha eliminado " + n + " de la lista negra.");
    server.send(200,"text/plain","OK"); 
  } else server.send(404,"text/plain","No encontrado");
}
void handleToBlack(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  delMacAllow(n); saveAllowToNVS(); addMacBlack(n); saveBlackToNVS();
  int idx=findPendingIdx(n); if(idx>=0){ for(int j=idx+1;j<pendingCount;j++) pending[j-1]=pending[j]; pendingCount--; }
  logEvent("Se ha movido " + n + " a la lista negra.");
  server.send(200,"text/plain","OK");
}
void handleToAllow(){ if (guard()) return;
  if (!server.hasArg("mac")){ server.send(400,"text/plain","Falta mac"); return; }
  String n; if(!normalizeMac(server.arg("mac"),n)){ server.send(400,"text/plain","MAC invalida"); return; }
  delMacBlack(n); saveBlackToNVS(); addMacAllow(n); saveAllowToNVS();
  int idx=findPendingIdx(n); if(idx>=0){ for(int j=idx+1;j<pendingCount;j++) pending[j-1]=pending[j]; pendingCount--; }
  logEvent("Se ha movido " + n + " a la lista blanca.");
  server.send(200,"text/plain","OK");
}

void handleSetAPSettings() {
  if (guard()) return;
  if (!server.hasArg("ssid") || !server.hasArg("pass")) {
    server.send(400, "text/plain", "Faltan SSID o Contraseña");
    return;
  }
  String new_ssid = server.arg("ssid");
  String new_pass = server.arg("pass");
  if (new_pass.length() < 8) {
      server.send(400, "text/plain", "Contraseña debe tener al menos 8 caracteres.");
      return;
  }

  saveAPConfigToNVS(new_ssid, new_pass);
  logEvent("Configuración de AP cambiada a " + new_ssid + ". Reiniciando...");
  server.send(200, "text/plain", "OK. Reiniciando el ESP32 con la nueva configuración.");
  delay(100);
  ESP.restart();
}

// ====== UI Scanner (/) ======
String htmlScanner(){
  return R"rawliteral(<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Scanner • ESP32</title>
<style>
:root{--bg:#12121e;--card:#1e1e2d;--txt:#e3e3ff;--muted:#8aa0ff;--bar:#5b8cff;--accent-bg:#5b8cff22}
*{box-sizing:border-box} body{margin:0;font-family:'Segoe UI',Roboto,Arial,sans-serif;color:var(--txt);background:var(--bg)}
.container{max-width:1100px;margin:20px auto;padding:0 16px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding:16px 20px;background:var(--card);border-radius:12px;box-shadow:0 8px 16px rgba(0,0,0,.3)}
.h1{font-size:2rem;font-weight:700;margin:0} .tag{font-size:.8rem;color:var(--muted);background:var(--accent-bg);padding:4px 10px;border-radius:20px;font-weight:600}
.btn{background:var(--accent);color:white;border:none;border-radius:8px;padding:10px 16px;font-size:.9rem;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#4a73e6}
.card{background:var(--card);border-radius:12px;padding:20px;box-shadow:0 8px 16px rgba(0,0,0,.3);margin-top:20px}
table{width:100%;border-collapse:separate;border-spacing:0 10px;margin-top:10px}
th{text-align:left;font-size:.8rem;color:var(--muted);padding:0 10px}
td{padding:12px 10px;border-bottom:1px solid #333;font-size:.9rem}
tr:last-child td{border-bottom:none}
.progress{height:8px;background:#333;border-radius:4px;overflow:hidden}
.progress>div{height:100%;background:var(--bar);transition:width .4s}
@media(max-width:600px){.header{flex-direction:column;gap:10px} .right{margin-top:10px}}
</style></head><body>
<div class="container">
  <div class="header">
    <div class="h1">ESP32 Network Scanner</div>
    <div class="tag">AP: <span id="ap-ssid"></span></div>
    <div>
      <a class="btn" href="/admin?pass=admin1234">Panel de Administración</a>
      <button class="btn" onclick="manualScan()">Escanear ahora</button>
    </div>
  </div>
  <div class="card">
    <small style="color:var(--muted)">Actualización automática cada 2 s. El escáner se ejecuta cada 12 s.</small>
    <table id="tbl">
      <thead>
        <tr>
          <th>#</th><th>SSID</th><th>BSSID</th><th>Seguridad</th><th>Canal</th><th>RSSI</th><th>Calidad</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>
</div>
<script>
function render(rows, apSsid){
  const tb=document.querySelector("#tbl tbody"); tb.innerHTML="";
  document.getElementById('ap-ssid').innerText = apSsid;
  rows.forEach((r,i)=>{
    const tr=document.createElement("tr");
    const bar=`<div class="progress"><div style="width:${r.quality}%"></div></div>`;
    tr.innerHTML=`<td>${i+1}</td><td>${r.ssid}</td><td><code>${r.bssid}</code></td><td>${r.security}</td><td>${r.channel}</td><td>${r.rssi} dBm</td><td>${r.quality}% ${bar}</td>`;
    tb.appendChild(tr);
  });
}
async function refresh(){
  try{
    const r=await fetch("/api/state?pass=admin1234");
    const state=await r.json();
    const rScan=await fetch("/api/scan");
    const networks=await rScan.json();
    render(networks, state.ap_ssid);
  }catch(e){console.error(e)}
}
function manualScan(){ fetch("/api/rescan").then(()=>setTimeout(refresh,1200)); }
setInterval(refresh,2000); refresh();
</script>
</body></html>)rawliteral";
}
void handleRoot(){ server.send(200, "text/html", htmlScanner()); }
void handleRescan(){ runScan(); server.send(200,"text/plain","OK"); }

// ====== UI Admin (/admin) ======
String htmlAdmin(){
  return R"rawliteral(<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panel de Administrador • ESP32</title>
<style>
:root{--bg:#12121e;--card:#1e1e2d;--txt:#e3e3ff;--muted:#8aa0ff;--ok:#2ecc71;--bad:#ff6b6b;--accent:#5b8cff;--edit:#ff9800}
*{box-sizing:border-box} body{margin:0;background:var(--bg);font-family:'Segoe UI',Roboto,Arial,sans-serif;color:var(--txt)}
.container{max-width:1100px;margin:20px auto;padding:0 16px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding:16px 20px;background:var(--card);border-radius:12px;box-shadow:0 8px 16px rgba(0,0,0,.3)}
.h1{font-size:2rem;font-weight:700;margin:0} .tag{font-size:.8rem;color:var(--muted);background:var(--accent-bg);padding:4px 10px;border-radius:20px;font-weight:600}
.btn{background:var(--accent);color:white;border:none;border-radius:8px;padding:10px 16px;font-size:.9rem;font-weight:600;cursor:pointer;transition:background .2s;text-decoration:none}
.btn.bad{background:var(--bad)} .btn.ok{background:var(--ok)} .btn.out{background:transparent;border:1px solid var(--accent);color:var(--accent)} .btn.edit{background:var(--edit)}
.btn:hover{background:#4a73e6}.btn.bad:hover{background:#ff4d4d}.btn.ok:hover{background:#25a35e}
.card{background:var(--card);border-radius:12px;padding:20px;box-shadow:0 8px 16px rgba(0,0,0,.3);margin-top:20px}
.row{display:flex;gap:20px;flex-wrap:wrap}.col{flex:1 1 300px}
table{width:100%;border-collapse:separate;border-spacing:0 10px} th,td{padding:12px 10px;border-bottom:1px solid #333;font-size:.9rem}
th{text-align:left;color:var(--muted);font-weight:700} tr:last-child td{border-bottom:none}
code{background:rgba(255,255,255,.06);padding:2px 6px;border-radius:6px}
.input-group{margin-bottom:15px} .input-group label{display:block;margin-bottom:5px;font-size:.9rem;color:var(--muted)}
.input-group input{width:100%;padding:10px;border-radius:8px;border:1px solid #444;background:#28283d;color:var(--txt)}
.btn-group{display:flex;gap:10px;flex-wrap:wrap} .btn-group .btn{flex:1}
.alias-container{display:flex;align-items:center;gap:10px} .alias-text{flex-grow:1}
.modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);display:flex;justify-content:center;align-items:center;opacity:0;visibility:hidden;transition:opacity .3s, visibility .3s}
.modal.show{opacity:1;visibility:visible}
.modal-content{background:var(--card);padding:25px;border-radius:12px;min-width:300px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,.5)}
.event-log{background:#28283d;border-radius:8px;padding:15px;max-height:250px;overflow-y:auto;font-family:monospace;font-size:12px}
.event-log-item{margin-bottom:8px;line-height:1.4} .event-log-time{color:var(--muted);margin-right:10px}
.status-indicator{font-size:.9rem;font-weight:600;padding:4px 10px;border-radius:20px}
.status-indicator.active{background:rgba(46,204,113,.2);color:var(--ok)}
.status-indicator.inactive{background:rgba(255,107,107,.2);color:var(--bad)}
</style></head><body>
<div class="container">
  <div class="header">
    <div class="h1">Panel de Administración</div>
    <div class="tag">Versión Empresarial</div>
    <a class="btn" href="/">Volver al Scanner</a>
  </div>

  <div class="card">
    <h3>Estado de la Red</h3>
    <p>Filtrado de acceso: <span id="flt-status" class="status-indicator"></span></p>
  </div>

  <div class="row">
    <div class="col card">
      <h3>Clientes Conectados</h3>
      <table id="tblConn"><thead><tr><th>MAC</th><th>Alias</th><th>Último Visto</th><th>RSSI</th><th>Acciones</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="col card">
      <h3>Dispositivos en Espera</h3>
      <table id="tblPend"><thead><tr><th>MAC</th><th>Alias</th><th>Visto Hace</th><th>Acción</th></tr></thead><tbody></tbody></table>
    </div>
  </div>

  <div class="row">
    <div class="col card">
      <h3>Lista Blanca</h3>
      <form class="input-group" onsubmit="return addAllow(event)">
        <label for="macAllow">Agregar MAC a la Lista Blanca</label>
        <div class="btn-group">
          <input class="input" id="macAllow" placeholder="AA:BB:CC:DD:EE:FF">
          <button class="btn ok" type="submit">Agregar</button>
        </div>
      </form>
      <table id="tblAllow"><thead><tr><th>MAC</th><th>Alias</th><th>Acciones</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="col card">
      <h3>Lista Negra</h3>
      <form class="input-group" onsubmit="return addBlack(event)">
        <label for="macBlack">Agregar MAC a la Lista Negra</label>
        <div class="btn-group">
          <input class="input" id="macBlack" placeholder="AA:BB:CC:DD:EE:FF">
          <button class="btn bad" type="submit">Bloquear</button>
        </div>
      </form>
      <table id="tblBlack"><thead><tr><th>MAC</th><th>Alias</th><th>Acciones</th></tr></thead><tbody></tbody></table>
    </div>
  </div>

  <div class="row">
    <div class="col card">
      <h3>Configuración de la Red ESP32</h3>
      <form class="input-group" onsubmit="return setAPSettings(event)">
        <label for="ap-ssid-input">SSID de la Red Principal</label>
        <input id="ap-ssid-input" type="text" required>
        <label for="ap-pass-input">Contraseña de la Red Principal</label>
        <input id="ap-pass-input" type="password" minlength="8" required>
        <div style="margin-top:15px" class="btn-group"><button class="btn ok" type="submit">Guardar y Reiniciar</button></div>
      </form>
    </div>
    <div class="col card">
      <h3>Herramientas Avanzadas</h3>
      <p style="margin-bottom: 5px; color:var(--muted)">Evil Twin Attack</p>
      <div class="btn-group">
        <button class="btn bad" onclick="startEvilTwin()">Iniciar</button>
        <button class="btn ok" onclick="stopEvilTwin()">Detener</button>
      </div>
      <p style="margin: 15px 0 5px; color:var(--muted)">Sniffing de Paquetes</p>
      <div class="btn-group">
        <button class="btn bad" onclick="startSniffer()">Iniciar</button>
        <button class="btn ok" onclick="stopSniffer()">Detener</button>
      </div>
    </div>
  </div>

  <div class="card">
      <h3>Log de Eventos</h3>
      <div id="eventLog" class="event-log"></div>
  </div>

</div>

<div id="modalAlias" class="modal">
  <div class="modal-content">
    <h4>Editar Alias</h4>
    <input type="hidden" id="modalMac">
    <div class="input-group"><input id="modalAliasInput" type="text" placeholder="Nombre del dispositivo"></div>
    <div class="btn-group">
      <button class="btn ok" onclick="saveAlias()">Guardar</button>
      <button class="btn out" onclick="closeModal()">Cancelar</button>
    </div>
  </div>
</div>

<script>
const PASS=(new URLSearchParams(location.search)).get('pass')||'';
const fmt=(ms)=>Math.round(ms/1000)+'s';
const modalAlias=document.getElementById('modalAlias');
const modalMacInput=document.getElementById('modalMac');
const modalAliasInput=document.getElementById('modalAliasInput');
let lastLogCount=0;

const fetchState=async()=>{
  try{
    const r=await fetch("/api/state?pass="+encodeURIComponent(PASS));
    const j=await r.json();

    document.getElementById('flt-status').innerText=j.filtering?'ACTIVO':'INACTIVO';
    document.getElementById('flt-status').className='status-indicator '+(j.filtering?'active':'inactive');
    document.getElementById('ap-ssid-input').value = j.ap_ssid;
    document.getElementById('ap-pass-input').value = j.ap_pass;

    const renderTable=(id, data, cols, actions)=>{
      const tb=document.querySelector(`#${id} tbody`); tb.innerHTML='';
      data.forEach(d=>{
        const tr=document.createElement('tr');
        const aliasHTML = `<span class="alias-text">${d.alias||''}</span> <button class="btn edit" onclick="openModal('${d.mac}', '${d.alias||''}')">✎</button>`;
        let rowHTML = `<td><code>${d.mac}</code></td><td>${aliasHTML}</td>`;
        if (cols.includes('seen')) rowHTML += `<td>${fmt(d.seen_ms)}</td>`;
        if (cols.includes('aid')) rowHTML += `<td>${d.aid}</td>`;
        if (cols.includes('rssi')) rowHTML += `<td>${d.rssi} dBm</td>`;
        rowHTML += `<td>${actions(d)}</td>`;
        tr.innerHTML = rowHTML;
        tb.appendChild(tr);
      });
    }

    renderTable('tblConn', j.connected, ['seen', 'aid', 'rssi'], d =>
      `<button class="btn bad" onclick="deauth('${d.mac}')">Desautenticar</button>`
    );
    renderTable('tblPend', j.pending, ['seen'], d =>
      `<button class="btn ok" onclick="approve('${d.mac}')">Aprobar</button><button class="btn bad" onclick="toBlack('${d.mac}')">Bloquear</button>`
    );
    renderTable('tblAllow', j.allowed, [], d =>
      `<button class="btn bad" onclick="delAllow('${d.mac}')">Eliminar</button><button class="btn out" onclick="toBlack('${d.mac}')">A Negra</button>`
    );
    renderTable('tblBlack', j.black, [], d =>
      `<button class="btn bad" onclick="delBlack('${d.mac}')">Eliminar</button><button class="btn ok" onclick="toAllow('${d.mac}')">A Blanca</button>`
    );

  }catch(e){console.error("Error fetching state:",e)}
}

const fetchLog=async()=>{
  try{
    const r=await fetch("/api/log?pass="+encodeURIComponent(PASS));
    const logData=await r.json();
    const logDiv=document.getElementById('eventLog');
    if(logData.length > lastLogCount){
      logDiv.innerHTML='';
      logData.forEach(event=>{
        const item=document.createElement('div');
        item.classList.add('event-log-item');
        item.innerHTML=`<span class="event-log-time">(${event.time})</span> ${event.message}`;
        logDiv.appendChild(item);
      });
      logDiv.scrollTop=logDiv.scrollHeight;
      lastLogCount=logData.length;
    }
  }catch(e){console.error("Error fetching log:",e)}
}

const openModal=(mac,alias)=>{
  modalMacInput.value=mac;
  modalAliasInput.value=alias||'';
  modalAlias.classList.add('show');
}
const closeModal=()=>modalAlias.classList.remove('show');
const saveAlias=()=>{
  fetch(`/set_alias?pass=${PASS}&mac=${modalMacInput.value}&alias=${encodeURIComponent(modalAliasInput.value)}`)
    .then(()=>{closeModal();fetchState();fetchLog();});
}
const addAllow=(ev)=>{if(ev)ev.preventDefault();const v=document.getElementById('macAllow').value;fetch(`/add?pass=${PASS}&mac=${encodeURIComponent(v)}`).then(()=>{document.getElementById('macAllow').value='';fetchState();fetchLog();});return false;}
const delAllow=(mac)=>fetch(`/del?pass=${PASS}&mac=${mac}`).then(()=>fetchState());
const approve=(mac)=>fetch(`/approve?pass=${PASS}&mac=${mac}`).then(()=>fetchState());
const addBlack=(ev)=>{if(ev)ev.preventDefault();const v=document.getElementById('macBlack').value;fetch(`/addb?pass=${PASS}&mac=${encodeURIComponent(v)}`).then(()=>{document.getElementById('macBlack').value='';fetchState();fetchLog();});return false;}
const delBlack=(mac)=>fetch(`/delb?pass=${PASS}&mac=${mac}`).then(()=>fetchState());
const toBlack=(mac)=>fetch(`/to_black?pass=${PASS}&mac=${mac}`).then(()=>fetchState());
const toAllow=(mac)=>fetch(`/to_allow?pass=${PASS}&mac=${mac}`).then(()=>fetchState());
const deauth=(mac)=>fetch(`/deauth?pass=${PASS}&mac=${mac}`).then(()=>fetchState());
const startEvilTwin=()=>fetch("/start_evil_twin?pass="+PASS).then(()=>fetchLog());
const stopEvilTwin=()=>fetch("/stop_evil_twin?pass="+PASS).then(()=>fetchLog());
const startSniffer=()=>fetch("/start_sniffer?pass="+PASS).then(()=>fetchLog());
const stopSniffer=()=>fetch("/stop_sniffer?pass="+PASS).then(()=>fetchLog());
const setAPSettings=(ev)=>{
  ev.preventDefault();
  const newSsid=document.getElementById('ap-ssid-input').value;
  const newPass=document.getElementById('ap-pass-input').value;
  fetch(`/set_ap_settings?pass=${PASS}&ssid=${encodeURIComponent(newSsid)}&pass=${encodeURIComponent(newPass)}`).then(r=>r.text()).then(t=>alert(t));
  return false;
}
setInterval(fetchState,2000); fetchState();
setInterval(fetchLog,2000); fetchLog();
</script>
</body></html>)rawliteral";
}
void handleAdmin(){
  if (guard()) return;
  server.send(200,"text/html", htmlAdmin());
}

// Sniffer callback
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  // Aquí puedes agregar tu lógica de análisis de paquetes
  Serial.println("Paquete detectado en modo Sniffer.");
  // Si quieres ver el contenido de los paquetes, descomenta la siguiente línea
  // Serial.printf("Tipo: %d, Tamaño: %d\n", type, ((wifi_promiscuous_pkt_t*)buf)->rx_ctrl.sig_len);
}

// ====== Setup / Loop ======
void setup(){
  Serial.begin(115200);
  delay(200);

  // LittleFS
  if(!LittleFS.begin(true)){
    Serial.println("An Error has occurred while mounting LittleFS");
    return;
  }

  // Listas desde NVS
  loadListsFromNVS();
  aliasPrefs.begin("mac_alias", false); // Initialize alias preferences
  aliasPrefs.end();

  loadAPConfigFromNVS();

  // Forzar agregar tu laptop en BLANCA si no está
  String my; normalizeMac(String(MY_LAPTOP_MAC), my);
  if (my.length()==17 && !macAllowed(my)) { 
    addMacAllow(my); 
    saveAliasToNVS(my, "Mi Laptop"); // Set a default alias
    saveAllowToNVS(); 
    logEvent("MAC " + my + " agregada a la lista blanca por defecto.");
  }
  
  logEvent("Sistema iniciado.");
  
  // Corregir modo de WiFi
  WiFi.mode(WIFI_AP);
  WiFi.onEvent(WiFiEventHandler);
  WiFi.softAP(ap_ssid.c_str(), ap_pass.c_str());

  // Configurar el servidor DNS para la redirección
  dnsServer.start(53, "*", WiFi.softAPIP());
  
  // Configurar sniffer callback
  esp_wifi_set_promiscuous_rx_cb(&sniffer);

  runScan();
  lastScan = millis();

  // Rutas Scanner
  server.on("/", HTTP_GET, handleRoot);
  server.on("/api/scan", HTTP_GET, handleApiScan);
  server.on("/api/rescan", HTTP_GET, handleRescan);

  // Rutas Admin
  server.on("/admin", HTTP_GET, handleAdmin);
  server.on("/api/state", HTTP_GET, handleApiState);
  server.on("/api/log", HTTP_GET, handleApiLog);
  server.on("/add", HTTP_GET, handleAddAllow);
  server.on("/del", HTTP_GET, handleDelAllow);
  server.on("/approve", HTTP_GET, handleApprove);
  server.on("/addb", HTTP_GET, handleAddBlack);
  server.on("/delb", HTTP_GET, handleDelBlack);
  server.on("/to_black", HTTP_GET, handleToBlack);
  server.on("/to_allow", HTTP_GET, handleToAllow);
  server.on("/set_alias", HTTP_GET, handleAddAlias);
  server.on("/deauth", HTTP_GET, handleDeauth);
  server.on("/start_evil_twin", HTTP_GET, handleEvilTwin);
  server.on("/stop_evil_twin", HTTP_GET, handleStopEvilTwin);
  server.on("/start_sniffer", HTTP_GET, handleStartSniffer);
  server.on("/stop_sniffer", HTTP_GET, handleStopSniffer);
  server.on("/set_ap_settings", HTTP_GET, handleSetAPSettings);

  server.begin();
  Serial.println("[HTTP] Servidor listo en http://192.168.4.1");
}

void loop(){
  server.handleClient();
  dnsServer.processNextRequest(); // Atender las peticiones DNS

  unsigned long now = millis();
  if (now - lastScan >= SCAN_INTERVAL_MS){ lastScan = now; runScan(); }

  static uint32_t t_rssi=0;
  if (millis()-t_rssi > 2000){ t_rssi = millis(); refreshRSSIConnected(); }

  static uint32_t t_prune=0;
  if (millis()-t_prune > 5000){ t_prune = millis(); prunePending(); }
}
