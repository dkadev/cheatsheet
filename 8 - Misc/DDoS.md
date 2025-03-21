## Theory

https://github.com/Karthikdude/DDOS-Attack-Guide

## DDoS Tools

### **MHDDoS**
- Best DDoS Attack Script Python3, (Cyber / DDos) Attack With 56 Methods
https://github.com/MatrixTM/MHDDoS
https://blog.elhacker.net/2025/01/ejemplos-ataques-ddos-capa-7-con-mhddos.html

**Methods**

💣 Layer7

- get GET | GET Flood
- post POST | POST Flood
- ovh OVH | Bypass OVH
- ovh RHEX | Random HEX
- ovh STOMP | Bypass chk_captcha
- stress STRESS | Send HTTP Packet With High Byte
- dyn DYN | A New Method With Random SubDomain
- downloader DOWNLOADER | A New Method of Reading data slowly
- slow SLOW | Slowloris Old Method of DDoS
- head HEAD | https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
- null NULL | Null UserAgent and ...
- cookie COOKIE | Random Cookie PHP 'if (isset($_COOKIE))'
- pps PPS | Only 'GET / HTTP/1.1\r\n\r\n'
- even EVEN | GET Method with more header
- googleshield GSB | Google Project Shield Bypass
- DDoSGuard DGB | DDoS Guard Bypass
- ArvanCloud AVB | Arvan Cloud Bypass
- Google bot BOT | Like Google bot
- Apache Webserver APACHE | Apache Expliot
- wordpress expliot XMLRPC | WP XMLRPC exploit (add /xmlrpc.php)
- CloudFlare CFB | CloudFlare Bypass
- CloudFlare UnderAttack Mode CFBUAM | CloudFlare Under Attack Mode Bypass
- bypass BYPASS | Bypass Normal AntiDDoS
- bypass BOMB | Bypass with codesenberg/bombardier
- 🔪 KILLER | Run many threads to kill a target
- 🧅 TOR | Bypass onion website

**Example:**

```
python3 start.py <1=method> <2=url> <3=socks_type> <4=threads> <5=proxylist> <6=rpc> <7=duration> <8=debug=optional>
```
- 1: Method (type of attack)
- 2: Target URL or IP Address
- 3: Proxy Version ([Proxy Usage](https://github.com/MHProDev/MHDDoS/wiki/Proxy-Support-!))
- 4: Proxy File ([Proxy File Format](https://github.com/MHProDev/MHDDoS/wiki/Proxy-Files))
- 5: Number of threads to use ([Multi Threading](https://en.wikipedia.org/wiki/Multithreading_\(computer_architecture\)))
- 6: RPC (Requests pre connection)
- 7: Duration (Time to finish attack in seconds)
- 8: Debug Mode (Optional)

#### GET Flood

```
python3 start.py GET http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```

#### POST Flood

```
python3 start.py POST http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```

#### HEAD Flood

El uso de los métodos HTTP **HEAD** y **CONNECT** en los ataques recientes es un ejemplo claro de cómo los atacantes están utilizando estrategias menos comunes pero igualmente efectivas para explotar los sistemas. Estos métodos, aunque diseñados con propósitos legítimos, pueden ser manipulados para infligir un impacto desproporcionado en la infraestructura objetivo.

El método **HEAD** es una solicitud HTTP diseñada para obtener los encabezados de una respuesta sin incluir el cuerpo del contenido. Esto lo hace _más ligero en términos de transferencia de datos, ya que no devuelve el contenido completo de la página solicitada_. Sin embargo, el servidor aún procesa la solicitud como si fuera una petición completa, generando los mismos encabezados que una respuesta GET.

```
python3 start.py HEAD http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```
#### Random HEX

Los ataques **DDoS de Random Hexadecimal** son una variante de los ataques de capa 7 diseñados para saturar aplicaciones web mediante la generación de solicitudes HTTP con **datos aleatorios en los parámetros**, **encabezados o incluso en el cuerpo de las solicitudes**. La clave de estos ataques está en que los valores aleatorios, usualmente representados en formato hexadecimal (por ejemplo, 0xABCDEF), dificultan que las contramedidas basadas en patrones predecibles (como WAFs) detecten o filtren el tráfico malicioso.

Un ejemplo seria _hxxp://victima.com/page?param=0x1A3F5B_

Dado que cada solicitud parece única debido al contenido aleatorio, es difícil implementar reglas basadas en patrones sin afectar el tráfico legítimo.

```
python3 start.py RHEX http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```

#### STRESS

Send HTTP Packet With High Byte

El método **STRESS** en MHDDoS es un tipo de ataque diseñado específicamente para saturar servidores mediante el envío de paquetes HTTP con un tamaño de bytes considerablemente grande. Este método apunta a sobrecargar no solo el ancho de banda del servidor, sino también sus recursos internos, como memoria y capacidad de procesamiento, al obligarlo a manejar solicitudes masivas con cargas de datos significativas. Es particularmente eficaz contra servidores web mal configurados o con capacidades limitadas para manejar grandes volúmenes de tráfico.

En esencia, el método STRESS combina características de ataques volumétricos (por el gran tamaño de los paquetes) con ataques de capa 7 (al usar protocolos HTTP), lo que lo convierte en una herramienta versátil para ataques de denegación de servicio distribuidos.

```
python3 start.py STRESS http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```

#### SlowLoris

Slowloris Old Method of DDoS

El ataque **SLOWLORIS** se centra en mantener abiertas múltiples conexiones HTTP al servidor objetivo, **utilizando la menor cantidad de recursos posible por parte del atacante**. El truco detrás de SLOWLORIS es enviar encabezados HTTP incompletos, lo que obliga al servidor a mantener las conexiones abiertas en espera de que se complete la solicitud. Esto puede saturar el pool de conexiones del servidor, dejando al resto de los clientes legítimos sin acceso.

```
python3 start.py SLOW http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```

#### Downloader

A New Method of Reading data slowly

El método **DOWNLOADER** en MHDDoS es muy similar a SLOWLORIS en su filosofía, pero agrega un enfoque adicional: el envío de solicitudes diseñadas para que el servidor descargue grandes cantidades de datos desde su propia infraestructura. Este ataque obliga al servidor a usar su ancho de banda y recursos internos para manejar solicitudes aparentemente legítimas, pero manipuladas para que se conviertan en herramientas de autoexplotación.

```
python3 start.py DOWNLOADER http://example.com 5 101 /opt/Valid8Proxy/proxies.txt 100 3600
```

### **CC-attack**
- Using Socks4/5 or http proxies to make a multithreading Http-flood/Https-flood (cc) attack.
https://github.com/Leeon123/CC-attack

### **slowhttptest**
- Application Layer DoS attack simulator
https://github.com/shekyan/slowhttptest

Application Layer DoS attacks, such as **[slowloris](http://ha.ckers.org/slowloris/)**, **[Slow HTTP POST](http://www.darkreading.com/vulnerability-management/167901026/security/attacks-breaches/228000532/index.html)**, **[Slow Read attack](https://community.qualys.com/blogs/securitylabs/2012/01/05/slow-read)** (based on TCP persist timer exploit) by draining concurrent connections pool, as well as **[Apache Range Header attack](https://github.com/shekyan/slowhttptest/wiki/ApacheRangeTest)** by causing very significant memory and CPU usage on the server.

Slowloris and Slow HTTP POST DoS attacks rely on the fact that the HTTP protocol, by design, requires requests to be completely received by the server before they are processed. If an HTTP request is not complete, or if the transfer rate is very low, the server keeps its resources busy waiting for the rest of the data. If the server keeps too many resources busy, this creates a denial of service. This tool is sending partial HTTP requests, trying to get denial of service from target HTTP server.

[Slow Read DoS attack](https://github.com/shekyan/slowhttptest/wiki/SlowReadTest) aims the same resources as slowloris and slow POST, but instead of prolonging the request, it sends legitimate HTTP request and reads the response slowly.

**Examples**

```
docker build -t slowhttptest:latest .
```

```
docker run slowhttptest:latest <slowhttptest args>
```

```
-H -g -c 10000 -r 2000
```

| option                    | description                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------ |
| -H, B, R or X             | specify to slow down in headers section or in message body, -R enables range test, -X enables slow read test |
| -g                        | generate statistics in CSV and HTML formats, pattern is slow_xxx.csv/html, where xxx is the time and date    |
| -c number of connections  | limited to 65539                                                                                             |
| -r connections per second | connection rate                                                                                              |


### Old / Deprecated
**hulk**
- HULK DoS tool ported to Go with some additional features.
https://github.com/grafov/hulk


https://github.com/palahsu/DDoS-Ripper
https://github.com/Tmpertor/Raven-Storm

HOIC
https://sourceforge.net/projects/high-orbit-ion-cannon/
LOIC
https://sourceforge.net/projects/loic/

## Proxies tools

**Valid8Proxy**
- Tool designed for fetching, validating, and storing working proxies.
https://github.com/spyboy-productions/Valid8Proxy

## Load testing tools

**Grafana k6**
- A modern load testing tool, using Go and JavaScript - [https://k6.io](https://k6.io)
https://github.com/grafana/k6

**Bombardier**
- Fast cross-platform HTTP benchmarking tool written in Go
https://github.com/codesenberg/bombardier

## Legal

AWS Policy 
https://aws.amazon.com/es/security/ddos-simulation-testing/
