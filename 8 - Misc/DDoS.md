## Theory

https://github.com/Karthikdude/DDOS-Attack-Guide
## Tools

**MHDDoS**
- Best DDoS Attack Script Python3, (Cyber / DDos) Attack With 56 Methods
https://github.com/MatrixTM/MHDDoS

**CC-attack**
- Using Socks4/5 or http proxies to make a multithreading Http-flood/Https-flood (cc) attack.
https://github.com/Leeon123/CC-attack

**slowhttptest**
- Application Layer DoS attack simulator
https://github.com/shekyan/slowhttptest

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

**hulk**
- HULK DoS tool ported to Go with some additional features.
https://github.com/grafov/hulk

### Deprecated
https://github.com/palahsu/DDoS-Ripper
https://github.com/Tmpertor/Raven-Storm

HOIC
https://sourceforge.net/projects/high-orbit-ion-cannon/
LOIC
https://sourceforge.net/projects/loic/

## Proxies

**Valid8Proxy**
- Tool designed for fetching, validating, and storing working proxies.
https://github.com/spyboy-productions/Valid8Proxy

## Load testing



## Legal

AWS Policy 
https://aws.amazon.com/es/security/ddos-simulation-testing/
