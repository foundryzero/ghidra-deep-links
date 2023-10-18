#!/bin/bash

echo "Installing Ghidra Deep Links..."

if pgrep snapd > /dev/null ; then
    echo "Warning: Ghidra Deep Links does not work from programs using snaps."
fi

read -p ".desktop install location [~/.local/share/applications]:" INSTALL_LOCATION

if [ -z "$INSTALL_LOCATION" ] ; then
    INSTALL_LOCATION="$HOME/.local/share/applications"
fi

echo "Install handler..."

cp os/linux/ghidra-opener.desktop $INSTALL_LOCATION
cp os/linux/push_to_socket $INSTALL_LOCATION
sed -i -e "s|INSTALL_LOCATION|$INSTALL_LOCATION|g" $INSTALL_LOCATION/ghidra-opener.desktop
chmod +x $INSTALL_LOCATION/push_to_socket

echo "Setting handler as default for disas:// links..."

xdg-mime default ghidra-opener.desktop x-scheme-handler/disas

echo "Done."

echo "Set GHIDRA_HOME to your ghidra installation to enable cold start link handling."

echo "The next time you open ghidra, install the extension and enable the plugin in both the main Ghidra window and any tools (eg Code Browser) you use."
