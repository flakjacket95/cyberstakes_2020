#!/bin/bash

set -e

mkdir -p ~/.config/chromium/NativeMessagingHosts/
NHPATH=~/.config/chromium/NativeMessagingHosts/

# See https://developer.chrome.com/apps/nativeMessaging#native-messaging-host-location for other locations
cp -r NativeMessagingHosts/* $NHPATH/.
sed -i "s|/etc/chromium/native-messaging-hosts|$NHPATH|" $NHPATH/com.security.password_manager.json

echo "Installed Secure Password Manager RCP"


