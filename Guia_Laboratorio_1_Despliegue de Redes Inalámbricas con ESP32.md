# GUÍA DE LABORATORIO 1: Despliegue de Redes Inalámbricas con ESP32

# **Objetivo General**

Configurar la ESP32 como servidor inalámbrico (punto de acceso) y cliente Wi-Fi, mostrando redes disponibles y su información.

## **1\. Objetivos específicos**

1. Comprender el concepto de **servidor inalámbrico** y cómo implementarlo en la ESP32.

2. Conocer el funcionamiento básico del **uso de redes inalámbricas** en entornos GNU/Linux y Windows.

3. Explorar el **servicio inalámbrico** mediante un servidor web embebido en la ESP32.

4. Analizar el funcionamiento del estándar **IEEE 802.11** en la práctica.

## **2\. Materiales**

* 1 × **ESP32** DevKit v1 o similar

* 1 × Cable USB para programación

* 1 × PC con **Arduino IDE** (o PlatformIO)

* Conexión a internet para instalar librerías

* Opcional: **Pantalla OLED SSD1306** (I2C)

* Smartphone o laptop para pruebas de conexión

## **3\. Fundamento teórico resumido**

* **Servidor inalámbrico**: Dispositivo que provee servicios (datos, aplicaciones, internet) por Wi-Fi.

* **Uso de redes inalámbricas**: Conexión entre dispositivos sin cables, basada en el estándar **IEEE 802.11**.

* **IEEE 802.11**: Conjunto de protocolos que definen la comunicación en redes Wi-Fi, incluyendo capas físicas, modulación y cifrado.

* **Punto de acceso (AP)**: Modo en el que un dispositivo crea su propia red Wi-Fi.

* **Estación (STA)**: Modo en el que un dispositivo se conecta a una red existente.

## **4\. Procedimiento**

### **4.1. Configuración como Punto de Acceso (AP)**

1. Abrir el **Arduino IDE**.

2. Seleccionar placa **ESP32 Dev Module** y puerto COM correcto.

3. Cargar el siguiente código:

\#include \<WiFi.h\>

const char\* ssid \= "ESP32\_LAB\_AP\_GRUPO\_6";  
const char\* password \= "123456789"; // Mínimo 8 caracteres

void setup() {  
  Serial.begin(115200);  
  WiFi.softAP(ssid, password);

  Serial.println("Punto de acceso iniciado");  
  Serial.print("SSID: "); Serial.println(ssid);  
  Serial.print("IP del AP: "); Serial.println(WiFi.softAPIP());  
}

void loop() {  
}

4. Subir el código y abrir el **Monitor Serial**.

5. Con un smartphone o laptop, buscar la red **ESP32\_LAB\_AP** y conectarse.

6. Verificar que la conexión funciona.

### **4.2. Configuración como Estación (STA)**

1. Modificar el código para conectar la ESP32 a una red existente:

\#include \<WiFi.h\>

const char\* ssid \= "Tu\_Red\_WiFi";  
const char\* password \= "Tu\_Clave\_WiFi";

void setup() {  
  Serial.begin(115200);  
  WiFi.begin(ssid, password);

  Serial.print("Conectando a ");  
  Serial.println(ssid);

  while (WiFi.status() \!= WL\_CONNECTED) {  
    delay(500);  
    Serial.print(".");  
  }

  Serial.println("\\nConectado\!");  
  Serial.print("IP asignada: ");  
  Serial.println(WiFi.localIP());  
}

void loop() {  
}

2. Subir el código y observar en el Monitor Serial que se conectó a la red.

### **4.3. Escaneo de redes disponibles**

1. Usar este código para listar redes cercanas:

\#include \<WiFi.h\>

void setup() {  
  Serial.begin(115200);  
  WiFi.mode(WIFI\_STA);  
  WiFi.disconnect();  
  delay(100);

  Serial.println("Escaneando redes...");  
  int n \= WiFi.scanNetworks();  
  Serial.println("Escaneo finalizado.");  
  if (n \== 0\) {  
    Serial.println("No se encontraron redes.");  
  } else {  
    for (int i \= 0; i \< n; \++i) {  
      Serial.print(i \+ 1);  
      Serial.print(": ");  
      Serial.print(WiFi.SSID(i));  
      Serial.print(" (");  
      Serial.print(WiFi.RSSI(i));  
      Serial.print(" dBm) ");  
      Serial.println((WiFi.encryptionType(i) \== WIFI\_AUTH\_OPEN) ? "Abierta" : "Segura");  
      delay(10);  
    }  
  }  
}

void loop() {}

2. Interpretar resultados:

   * **SSID** → Nombre de la red

   * **RSSI** → Potencia de señal

   * **Tipo de cifrado** → Seguridad

## **5\. Actividades a realizar**

* Completar la tabla con datos de redes detectadas:

| N° | SSID | RSSI (dBm) | Seguridad | Canal |
| ----- | ----- | ----- | ----- | ----- |
| 1 | MiRedCasa | \-60 | WPA2 | 6 |
| 2 | Oficina\_AP | \-75 | WPA3 | 11 |

* Comparar los resultados obtenidos en GNU/Linux (con nmcli o iwlist) y en Windows (con netsh wlan show networks).

* Responder:

  1. ¿Cuál es la diferencia entre un AP y una STA?

  2. ¿Qué estándar IEEE 802.11 es más común en las redes detectadas?

## **6\. Resultados esperados**

* La ESP32 funcionando como **AP** y **STA**.

* Listado de redes cercanas con su potencia y tipo de seguridad.

* Evidencia fotográfica de conexión y escaneo.

## **7\. Conclusiones**

* Identificar la importancia del despliegue y configuración segura de redes inalámbricas.

* Relacionar la práctica con los fundamentos del estándar IEEE 802.11.

