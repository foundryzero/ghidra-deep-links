#!/bin/bash

echo "Installing Ghidra Deep Links..."

if pgrep snapd > /dev/null; then
    echo "Warning: Ghidra Deep Links does not work from programs using snaps."
fi

read -p ".desktop install location [~/.local/share/applications]:" INSTALL_LOCATION

if [ -z "$INSTALL_LOCATION" ] ; then
    INSTALL_LOCATION="$HOME/.local/share/applications"
fi

cd $INSTALL_LOCATION

echo "Downloading handler..."

curl -f -O "https://raw.githubusercontent.com/foundryzero/ghidra-deep-links/main/os/linux/ghidra-opener.desktop"
sed -i -e "s|INSTALL_LOCATION|$INSTALL_LOCATION|g" ghidra-opener.desktop

curl -f -O "https://raw.githubusercontent.com/foundryzero/ghidra-deep-links/main/os/linux/push_to_socket"
chmod +x push_to_socket

echo "Setting handler as default for disas:// links..."

xdg-mime default ghidra-opener.desktop x-scheme-handler/disas

cd - > /dev/null

echo "Done."

echo "Set GHIDRA_HOME to your ghidra installation to enable cold start link handling."

echo "The next time you open ghidra, install the extension and enable the plugin in both the main Ghidra window and any tools (eg Code Browser) you use."
