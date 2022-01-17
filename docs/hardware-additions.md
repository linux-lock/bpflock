# Hardware additions protection

## 1. USB additions protection

### 1.1 Introduction

`usblock` - Implements restrictions to lock-down USB devices.
When connected, the USB device will be shown on the system
but not authorized to be used, this allows to **restrict**
some bad USB and poisontap attack types, like emulating an Ethernet device over USB to hijack network traffic.

`usblock` supports blocking **new** USB devices at runtime without changing your machine configuration.

This is particulary useful if you do not trust the USB ports
of your servers and devices. Coupled with a remote access, you can easily control when to activate or deactivate those same USB interfaces.

Note: protecting machines from attackers that have unlimited 
physicall access to perform different scenarios is a lost
case.
