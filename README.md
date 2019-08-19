# DESFire AES library

Designed for linux, and also ESP32 ESP-IDF building

Simple C library to talk to NXP MIFARE DESFire EV1 cards using AES.
Includes function to format card and convert master key to AES and perform various operations on DESFire cards.

Does not include the low level functions to actuall talk to cards, you bolt those in - this does the DESFire bit.

Copyright (c) 2019 Adrian Kennard, Andrews & Arnold Limited, see LICENSE file (GPL)
