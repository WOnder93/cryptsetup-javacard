#!/bin/bash

PROJECT_HOME="$(dirname "$0")/.."

if [ "$1" = '-?' ] || [ "$1" = '-h' ] || [ "$1" = '--help' ] || [ "$#" -lt 4 ]; then
    echo "Open the given LUKS device using a key stored on the card."
    echo
    echo "Usage: $0 PUBKEY_FILE TERMINAL_NAME DEVICE NAME"
    echo
    echo "  PUBKEY_FILE   -- the file containing the card's public key"
    echo "  TERMINAL_NAME -- the name of the JavaCard terminal to use"
    echo "  DEVICE        -- the device to format"
    echo "  NAME          -- the name of the device mapper mapping to create"
    exit 0
fi
PUBKEY_FILE="$1"
TERMINAL_NAME="$2"
DEVICE="$3"
NAME="$4"

if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME="$(bash "$PROJECT_HOME/scripts/find_java.sh")"
    if [ -z "$JAVA_HOME" ]; then
        echo "ERROR: You must set JAVA_HOME to your JDK path!" 1>&2
        echo "ERROR:   e. g. JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 $0 [...]" 1>&2
        exit 1
    fi
fi

CLIENT_PATH="$PROJECT_HOME/JCKeyStorage/dist/JCKeyStorage.jar"

UUID="$(cryptsetup -q luksUUID "$DEVICE")"

if [ -z "$UUID" ]; then exit 1; fi

echo "Unlocking partition $UUID..."

TMP_DIR=$(mktemp -d)
if [ -z "$TMP_DIR" ]; then exit 1; fi

FLAG="$TMP_DIR/flag"
mkfifo "$FLAG" || { rm -rf "$TMP_DIR"; exit 1; }

"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" loadkey -u "$UUID" -o >(cryptsetup -q --master-key-file /dev/stdin luksOpen "$DEVICE" "$NAME" && : >"$FLAG") || { rm -rf "$TMP_DIR"; exit 1; }

# Wait for cryptsetup to finish:
cat "$FLAG" >/dev/null

rm -rf "$TMP_DIR"

echo "Successfully opened device '$DEVICE' as '$NAME'!"
