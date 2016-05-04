#!/bin/bash

if [ "$1" = '-?' ] || [ "$1" = '-h' ] || [ "$1" = '--help' ]; then
    echo "Install the applet on a card."
    echo
    echo "Usage: $0 [ARGS...]"
    echo
    echo "  ARGS -- extra arguments to pass to GlobalPlatform (e. .g -r 'My Reader')"
    exit 0
fi

PROJECT_HOME="$(dirname "$0")/.."

if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME="$(bash "$PROJECT_HOME/scripts/find_java.sh")"
    if [ -z "$JAVA_HOME" ]; then
        echo "ERROR: You must set JAVA_HOME to your JDK path!" 1>&2
        echo "ERROR:   e. g. JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 $0 [...]" 1>&2
        exit 1
    fi
fi

APPLET_PACKAGE_AID='0x4a:0x43:0x4b:0x65:0x79:0x70:0x6b:0x67'
APPLET_PACKAGE=applets
APPLET_CLASS="$APPLET_PACKAGE.KeyStorageApplet"
APPLET_AID='0x4a:0x43:0x4b:0x65:0x79:0x53:0x74:0x6f:0x72:0x61:0x67:0x65'
APPLET_VERSION=1.0

OUT_PATH=$(mktemp -d)

APPLET_PATH="$PROJECT_HOME/JCKeyStorage/src/applets"
APPLET_SOURCE="$APPLET_PATH/KeyStorageApplet.java"

JCDK_PATH="$PROJECT_HOME/ext/java_card_kit-2_2_2"

echo "Compiling the applet..."

# Compile the class file:
"$JAVA_HOME/bin/javac" -d "$OUT_PATH" -classpath "$OUT_PATH:$JCDK_PATH/lib/api.jar" -sourcepath "$APPLET_PATH" -target 1.2 -g:none -Xlint -Xlint:-options -Xlint:-serial -source 1.3 "$APPLET_SOURCE" || { rm -rf "$OUT_PATH"; exit 1; }

# Convert to CAP:
bash "$JCDK_PATH/bin/converter" -verbose -nobanner -out CAP EXP -classdir "$OUT_PATH" -exportpath "$JCDK_PATH/api_export_files" -applet "$APPLET_AID" "$APPLET_CLASS" "$APPLET_PACKAGE" "$APPLET_PACKAGE_AID" "$APPLET_VERSION" || { rm -rf "$OUT_PATH"; exit 1; }

read -sp 'Enter the master password: ' MASTER_PWD || { rm -rf "$OUT_PATH"; exit 1; }; echo
read -sp 'Confirm the master password: ' CONFIRM_PWD || { rm -rf "$OUT_PATH"; exit 1; }; echo

if [ "$CONFIRM_PWD" != "$MASTER_PWD" ]; then
    echo "ERROR: The passwords do not match!" 1>&2
    exit 1
fi

MASTER_PWD="$(echo -n "$MASTER_PWD" | hexdump -v -e '/1 "%02X"')"

echo "Installing the applet using GlobalPlatformPro..."

# Install the applet:
"$JAVA_HOME/bin/java" -jar "$PROJECT_HOME/ext/gp.jar" --reinstall "$OUT_PATH/$APPLET_PACKAGE/javacard/$APPLET_PACKAGE.cap" --params "$MASTER_PWD" "$@" || { rm -rf "$OUT_PATH"; exit 1; }

rm -rf "$OUT_PATH"

echo "Applet has been installed successfully! (Unless you see an error message from GPPro - it doesn't set the exit code properly...)"