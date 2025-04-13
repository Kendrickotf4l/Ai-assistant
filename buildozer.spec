[app]
title = AI Assistant
package.name = aichat
package.domain = org.ai
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,ttf,json
version = 1.0

# Keep all dependencies (no size optimization)
requirements = 
    python3,
    kivy==2.2.1,
    pyjnius,
    requests,
    pycryptodome,
    numpy,
    beautifulsoup4,
    pillow,
    matplotlib,
    tkinter

# Full permissions
android.permissions = 
    INTERNET,
    NFC,
    BLUETOOTH,
    BLUETOOTH_ADMIN,
    ACCESS_NETWORK_STATE,
    ACCESS_WIFI_STATE,
    WRITE_EXTERNAL_STORAGE,
    READ_EXTERNAL_STORAGE

# Disable all optimizations
android.strip = False
android.no-compile-pyo = False
android.optimize = 0

# NDK/SDK settings
android.api = 33
android.minapi = 21
android.ndk_path = /home/runner/.buildozer/android/platform/android-ndk-r25b
android.sdk_path = /home/runner/.buildozer/android/platform/android-sdk
android.arch = arm64-v8a

# Extra build flags
android.extra_libs = 
    libbluetooth.so,
    libnfc.so

[buildozer]
log_level = 2
