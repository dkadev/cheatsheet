# Security standards
- [OWASP Mobile Security Project](https://www.owasp.org/index.php/OWASP_Mobile_Security_Project)
- [OWASP Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs)
- [OWASP Mobile Security Testing Guide (MSTG)](https://github.com/OWASP/owasp-mstg)
- [OWASP MASTG Checklists](https://mas.owasp.org/MASTG)

# Resources
- [Mobile app pentest cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
- [Android security awesome](https://github.com/ashishb/android-security-awesome)
- [Android security reference](https://github.com/doridori/Android-Security-Reference)
- [Awesome-linux-android-hacking](https://github.com/pfalcon/awesome-linux-android-hacking)
- [iOS security awesome](https://github.com/ashishb/osx-and-ios-security-awesome)
- [awesome-iOS-resource](https://github.com/aozhimin/awesome-iOS-resource)
- [Mobile security wiki](https://mobilesecuritywiki.com/)
- [iPhone wiki](https://www.theiphonewiki.com/wiki/Main_Page)
- [Nyxbone](http://www.nyxbone.com/malware/android_tools.html)
- [Nowhere](https://n0where.net/best-android-security-resources/)
- [Secmobi](https://github.com/secmobi/wiki.secmobi.com)
- Conect USB to WSL https://learn.microsoft.com/en-us/windows/wsl/connect-usb
# Analysis

## Static
Consiste en examinar el código y los archivos de la aplicación sin ejecutarla, buscando vulnerabilidades en su estructura y configuración.

1. **Android APK**:
   - Decompila archivos APK utilizando herramientas como [Jadx](https://github.com/skylot/jadx) o [Bytecode-Viewer](https://github.com/Konloch/bytecode-viewer).
   - Identifica dependencias inseguras mediante [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck).
   - Escanea en busca de secretos y endpoints con [apkleaks](https://github.com/dwisiswant0/apkleaks).
   - Valida configuraciones de seguridad con [semgrep-rules-android-security](https://github.com/mindedsecurity/semgrep-rules-android-security).
2. **iOS IPA**:
   - Examina archivos IPA desempaquetados para identificar configuraciones inseguras.
   - Revisa plist, binarios y otros archivos relevantes.

## Dynamic
Este enfoque evalúa la aplicación en tiempo de ejecución, observando cómo interactúa con el entorno y manejando datos.

1. **Android**:
   - Usa Frida para manipular y analizar el comportamiento de la aplicación.
   - Intercepta tráfico de red con Burp Suite.
   - Configura Magisk y AlwaysTrustUserCerts para superar restricciones de certificados.
2. **iOS**:
   - Intercepta tráfico HTTPS con Burp Suite y supera SSL pinning.
   - Realiza análisis en vivo con Frida para entender el funcionamiento de la app.

# Android

[Cómo montar un laboratorio de pentesting para Android en Windows](https://lobuhisec.medium.com/c%C3%B3mo-montar-un-laboratorio-de-pentesting-para-android-en-windows-4b5c627ea67a)

## Herramientas Requeridas
- **Android Studio**: Herramienta principal para crear y ejecutar emuladores de dispositivos Android. (Se puede hacer uso de otro emulador de Android como Genymotion).
- **ADB (Android Debug Bridge)**: Utilidad para interactuar con dispositivos/emuladores mediante comandos desde la terminal.
- **Magisk y AlwaysTrustUserCerts**: Soluciones para rootear emuladores y permitir que acepten certificados no confiables a nivel de sistema.
- **Frida**: Toolkit para análisis dinámico que permite inyectar scripts en aplicaciones durante su ejecución.
- **MobSF**: Marco automatizado para realizar análisis estático y dinámico de aplicaciones móviles.

## Pasos para el Laboratorio
1. **Instalar Android Studio**: Configura un emulador, eligiendo entre opciones con o sin Google Play Store, dependiendo de tus necesidades.
2. **Rootear el emulador**:
   - Utiliza [rootAVD](https://github.com/newbit1/rootAVD) para habilitar privilegios de root en los emuladores.
3. **Configurar Burp Suite**: Activa un proxy para interceptar y analizar tráfico de red.
4. **Configurar certificados**:
   - Usa el módulo AlwaysTrustUserCerts para garantizar que Burp Suite sea confiable para el emulador.
5. **Instrumentación con Frida**:
   - Instala el servidor Frida en el emulador para realizar análisis dinámico y bypass de medidas de seguridad.

## Guía ejemplo
1. Instalar Android Studio
2. Iniciar un AVD Android 11 API 30 maximo
3. rootAVD https://gitlab.com/newbit/rootAVD
https://www.andnixsh.com/2023/12/how-to-root-avd-android-virtual-device.html

```
set PATH=%LOCALAPPDATA%\Android\Sdk\platform-tools;%PATH%
```

```
./rootAVD.sh ListAllAVDs
```

```
./rootAVD.sh system-images/android-33/google_apis_playstore/x86_64/ramdisk.img s
```

4. Instalar módulo en Magisk https://github.com/NVISOsecurity/MagiskTrustUserCerts
5. Configurar proxy Burp en AVD 
6. Convertir a .crt y añadir certificado Burp a la cadena mediante el método normal
7. Reiniciar
8. SSL Pinning bypass con Frida https://github.com/LabCIF-Tutorials/Tutorial-AndroidNetworkInterception
https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/

Servidor:
```
adb push frida-server-16.5.9-android-x86 /sdcard/Download
adb shell
generic_x86_arm:/ $ su
generic_x86_arm:/ # cd /data/local/tmp
generic_x86_arm:/data/local/tmp # cp /sdcard/Download/frida-server-16.5.9-android-x86 .
generic_x86_arm:/data/local/tmp # chmod +x frida-server-16.5.9-android-x86
generic_x86_arm:/data/local/tmp # ./frida-server-16.5.9-android-x86  &
[1] 11627
```

Cliente:
```
frida-ps -Uai
```

```
frida -U --codeshare akabe1/frida-multiple-unpinning -f app.id
```

9. MobSF https://mobsf.github.io/docs/#/running_mobsf_docker

```
docker run -it --rm -p 8000:8000 -p 1337:1337 --add-host=host.docker.internal:host-gateway -e MOBSF_ANALYZER_IDENTIFIER=emulator-5554 opensecurity/mobile-security-framework-mobsf:latest
```

---

## How to root AVDs without Play Store (Google APIs) out of the box

- open a terminal -> win + r `cmd`
    
    - add emulator to your PATH
    - find your AVD
    - launch your AVD with the `-writable-system` argument
    
    ```
     set PATH=%LOCALAPPDATA%\Android\Sdk\emulator;%PATH%
     emulator -list-avds
     	Pixel_4_API_29
     emulator -avd Pixel_4_API_29 -writable-system
    ```
    

open a 2nd terminal -> win + r `cmd`

- enter the following commands one by one

```
 set PATH=%LOCALAPPDATA%\Android\Sdk\platform-tools;%PATH%
 adb root
 adb shell avbctl disable-verification
 adb disable-verity
 adb reboot
 adb root
 adb remount
 adb shell
 generic_x86_64:/ #
```

---

## Android Studio
### Change Location
Change geographic area (useful for some apps available via Play Store only in specific areas):

`Extended Controls > Location > Save Point > Set Location`

### Root access
Play Store images:
- Devices without Play Store --> Root access YES
- Devices with Play Store --> Root access NO

In the second case use rootAVD.

### Increase RAM in Play Store images
Play store image have gui locked ram size. To modify it:
```
1) right click on the device > show on disk > config.ini > hw.ramSize=newvalue
2) file > reload from disk
```

### How to set burp as proxy in Android Studio
1) Settings > Tools > Emulator > Untick Launch in a tool window
![image](https://github.com/midist0xf/pentesting-notes/assets/45259951/fa9545fc-62db-45a7-b829-1962d31cd140)
2) In the standalone Emulator window > Extended Controls > Proxy > 192.168.56.1:8080
![image](https://github.com/midist0xf/pentesting-notes/assets/45259951/60e3cd2f-313c-42fb-a82b-fe8ba2a1a4f2)
3) In burp Proxy tab set the listening interface 192.168.56.1:8080
![image](https://github.com/midist0xf/pentesting-notes/assets/45259951/90ee48f9-a091-49f4-9c2d-1f1f318c004d)

---
# iOS

[Modern iOS Pentesting (No Jailbreak Needed)](https://dvuln.com/blog/modern-ios-pentesting-no-jailbreak-needed)

## Herramientas Requeridas
- **MacOS con Xcode**: Herramienta oficial de Apple para desarrollo y simulación en iOS.
- **Frida**: Instrumentación dinámica para analizar aplicaciones en dispositivos y simuladores.
- **MobSF**: Marco automatizado para análisis estático y dinámico.
- **ipainstaller**: Utilidad para instalar archivos IPA en dispositivos no jailbreak.
- **Burp Suite**: Proxy para interceptar y analizar tráfico HTTPS.

## Pasos para el Laboratorio
1. Configura un simulador de iOS utilizando Xcode.
2. Configura Burp Suite como proxy e instala su certificado en el dispositivo/simulador.
3. Usa Frida para instrumentar aplicaciones:
   - Conecta Frida a un dispositivo o simulador.
   - Inyecta scripts para analizar y modificar comportamientos.
4. Analiza aplicaciones IPA con MobSF para identificar vulnerabilidades y configuraciones inseguras.

## Extract an IPA file from device
To extract an IPA file of an installed app from a jailbroken iPhone to your PC, you can use a tool like Filza File Manager on your iPhone and SCP (Secure Copy Protocol) to transfer the file. Here's how:

1. **Install Filza File Manager on iPhone**:
   - Open Cydia or Sileo on your jailbroken iPhone.
   - Search for and install `Filza File Manager`.

2. **Locate the App's Directory**:
   - Open Filza on your iPhone.
   - Navigate to `/var/containers/Bundle/Application/` or `/var/mobile/Containers/Bundle/Application/`.
   - Find the folder corresponding to the app you want to extract. The folders are usually named with UUIDs, so you may need to open them to identify the correct app by its `Info.plist` file.

3. **Copy the App's .app Folder**:
   - Once you find the correct app folder, copy the `.app` folder to a location you can easily access, like `/var/mobile/Documents/`.

4. **Create an IPA File**:
   - Compress the `.app` folder into a `.zip` file using Filza.
   - Rename the `.zip` file to `.ipa`.

5. **Transfer the IPA File to Your PC**:
   - Ensure OpenSSH is installed on your iPhone (as described in the previous response).
   - Use SCP to transfer the file from your iPhone to your PC. Open a terminal on your PC and use the following command:
     ```
     scp root@<iPhone_IP_address>:/var/mobile/Documents/<app_name>.ipa <destination_path_on_PC>
     ```
   - Replace `<iPhone_IP_address>` with your iPhone's IP address, `<app_name>.ipa` with the name of your IPA file, and `<destination_path_on_PC>` with the path where you want to save the file on your PC.

By following these steps, you should be able to extract and transfer the IPA file of an installed app from your iPhone to your PC.


---
# Tools

## MobSF
**Mobile Security Framework (MobSF):** Herramienta versátil para análisis estático y dinámico que soporta Android, iOS y Windows.

Repositorio: [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)

Comandos básicos:
```bash
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

## rootAVD
**Script para rootear AVDs en Android Studio:** Simplifica el proceso de habilitar acceso root en emuladores de Android.

Repositorio: [rootAVD](https://github.com/newbit1/rootAVD)

## Frida
*Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. Learn more at frida.re.*
- https://github.com/frida/frida
- https://medium.com/my-infosec-write-ups/frida-installation-40f52845ae98

```
# install frida tools
pip install frida-tools

# download frida-agent 
# detect device arch
adb shell
getprop ro.product.cpu.abi

# download the corresponding server release at https://github.com/frida/frida/releases
# install frida-server
adb devices -l 
adb push frida-server /data/local/tmp/frida-server
adb shell
su
chmod +x /data/local/tmp/frida-server
/data/local/tmp/frida-server
```

**Basic commands**
```
#To list the available devices for frida
frida-ls-devices

# List running processes
$ frida-ps -U

# List running applications
$ frida-ps -Ua

# List installed applications
$ frida-ps -Uai

# Connect Frida to the specific device
$ frida-ps -D 0216027d1d6d3a03
```

**SSL Pinning Bypass**
- https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/

## adb
```
# adb path if you installed Android Studio on Windows
C:\Users\<Username>\AppData\Local\Android\Sdk\platform-tools
```

**Basic commands**
```
# adb with multiple device
adb devices 
adb -s xxxxxxx shell

# extract apk via apk extractor
play store > apk extractor

# extract apk via adb (https://stackoverflow.com/questions/4032960/how-do-i-get-an-apk-file-from-an-android-device)
adb shell pm list packages
# If you can't recognize the app from the list of package names, try finding the app in Google Play using a browser. The URL for an app in Google Play contains the package name
# get full path for the package
adb shell pm path com.example.someapp
# pull the apk 
adb pull /data/app/com.example.someapp-2.apk path/to/desired/destination

# install apk via Android Studio
drag and drop the apk on the emulator
# install apk via adb
>adb -s emulator-5554 install C:\Users\<username>\myapp\base.apk
```

## jadx
*DEX to Java decompiler*
- https://github.com/skylot/jadx

## bytecode-viewer
*A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More). 6 Built-in Java decompilers: Krakatau, CFR, Procyon, FernFlower, JADX, JD-GUI*
- https://github.com/Konloch/bytecode-viewer/

## semgrep-rules-android-security
*A collection of Semgrep rules derived from the OWASP MASTG specifically for Android applications.*
- https://github.com/mindedsecurity/semgrep-rules-android-security
```
/.local/bin/semgrep -c ./rules/ /mnt/c/Users/xxxx/decompiled_by_jadx/
```
 
## apkid
*Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android*
- https://github.com/rednaga/APKiD
```
pip install apkid
git clone https://github.com/rednaga/APKiD
cd APKiD/
docker build . -t rednaga:apkid
docker/apkid.sh ~/reverse/targets/android/example/example.apk
```

## dependencycheck
*OWASP dependency-check is a software composition analysis utility that detects publicly disclosed vulnerabilities in application dependencies.*
- https://github.com/jeremylong/DependencyCheck/releases 
```
dependency-check\bin\dependency-check.bat -f HTML --out ./ -s ./source
```

## apkleaks
*Scanning APK file for URIs, endpoints & secrets.*
- https://github.com/dwisiswant0/apkleaks
```
pip install apkleaks
apkleaks -f C:\Users\xxxxxx\Desktop\myapp.apk
docker run -it --rm -v /tmp:/tmp dwisiswant0/apkleaks:latest -f /tmp/file.apk
```

## gmapsapiscanner
*Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.*
- https://github.com/ozguralp/gmapsapiscanner.git
- https://stackoverflow.com/questions/62454340/how-to-securely-use-google-map-api-key-on-android
- https://stefma.medium.com/something-about-google-api-keys-how-to-secure-them-and-what-firebase-got-to-do-with-this-e10473637ed3
```
python3 maps_api_scanner_python3.py
```

## Android-App-Link-Verification-Tester
*Checks if an Android application has successfully completed the "App Link Verification" process for Android App Links.*
- https://github.com/inesmartins/Android-App-Link-Verification-Tester
```
python3 deeplink_analyser.py -op list-all -apk ~/Downloads/example.apk
python3 Android-Deep-Link-Analyser/deeplinks_analyser.py -op list-applinks -m <path-to-android-manifest> -s <path-to-strings-file>
```

## apkcombo
*Download old APK, useful to test if updates are forced*
- https://apkcombo.com/

## Malimite
*iOS and macOS Decompiler*
https://github.com/LaurieWired/Malimite

# How to patch an apk
```
# tools paths if you installed Android Studio on Windows
C:\Users\xxx\AppData\Local\Android\Sdk\build-tools\34.0.0 (zipalign, apksigner)
C:\Program Files\Android\Android Studio\jbr\bin (jarsigner y keytool)
```
**Decompile -> Modify -> Repack -> Re-Sign**
1) `apktool d target_apk.apk`
2) for example, add to the manifest `<application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:name="com.xxx.xxx.xxx" android:theme="@style/AppTheme">`
3) `apktool b --output rebuilt.apk target_apk`
4) `zipalign -v 4 rebuilt.apk rebuilt-aligned.apk`
5) `keytool -genkey -v -keystore key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias test-apk`
6) `apksigner sign --ks keystore --ks-pass pass:password rebuilt-aligned.apk`

# How to root Android Studio Emulator 
- https://www.youtube.com/watch?v=qQicUW0svB8

# How to install Burp certificate 
The first step does not install the certificate at System level, only at User level:

`Settings > Security > Encryption & Credentials > Install from SD card > Drag and drop/select cacert.der`

Use Magisk module AlwaysTrustUserCerts to install the certificate at System level:

`Magisk > Modules > Install from storage > Downloads > Select AlwaysTrustUserCerts.zip > Reboot`

https://github.com/NVISOsecurity/MagiskTrustUserCerts

