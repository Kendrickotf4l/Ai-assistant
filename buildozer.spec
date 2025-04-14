[app]
title = AIMHigh Pro
package.name = aimhighpro
package.domain = org.aimhigh
source.dir = .
source.include_exts = py,png,jpg,kv,ttf,glsl
version = 1.0
requirements = 
    python3,
    kivy==2.1.0,
    numpy,
    pillow,
    opencv-python-headless,
    mediapipe,
    transformers,
    pyttsx3
android.permissions = INTERNET, CAMERA, RECORD_AUDIO
android.api = 31
android.ndk = 25b
android.arch = arm64-v8a
p4a.branch = 2023.08.24
