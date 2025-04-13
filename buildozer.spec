[app]
title = AI Assistant
package.name = aichat
package.domain = org.ai
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,pyjnius,android,requests,pycryptodome,numpy,beautifulsoup4,pillow
orientation = portrait
osx.python_version = 3
osx.kivy_version = 2.0.0
fullscreen = 0
android.permissions = INTERNET,NFC,BLUETOOTH,BLUETOOTH_ADMIN,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE
android.api = 30
android.minapi = 21
android.ndk = 19b
android.arch = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1