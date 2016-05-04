#!/bin/bash

PROJECT_HOME="$(dirname "$0")/.."

if [ "$1" = '-?' ] || [ "$1" = '-h' ] || [ "$1" = '--help' ] || [ "$#" -lt 4 ]; then
    echo "Create a new LUKS partition."
    echo
    echo "Usage: $0 PUBKEY_FILE TERMINAL_NAME DEVICE KEY_SIZE"
    echo
    echo "  PUBKEY_FILE   -- the file containing the card's public key"
    echo "  TERMINAL_NAME -- the name of the JavaCard terminal to use"
    echo "  DEVICE        -- the device to format"
    echo "  KEY_SIZE      -- the key size in bytes"
    exit 0
fi
PUBKEY_FILE="$1"
TERMINAL_NAME="$2"
DEVICE="$3"
KEY_SIZE="$4"

if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME="$(bash "$PROJECT_HOME/scripts/find_java.sh")"
    if [ -z "$JAVA_HOME" ]; then
        echo "ERROR: You must set JAVA_HOME to your JDK path!" 1>&2
        echo "ERROR:   e. g. JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 $0 [...]" 1>&2
        exit 1
    fi
fi

function join_strings { local d=$1; shift; echo -n "$1"; shift; printf "%s" "${@/#/$d}"; }
function from_hex { [ "$#" == 0 ] || printf "$(echo -n '\x'; join_strings '\x' $*)"; }

CLIENT_PATH="$PROJECT_HOME/JCKeyStorage/dist/JCKeyStorage.jar"
TMP_PASSWORD="dummy"

echo "Generating the key and formatting the partition..."

TMP_DIR=$(mktemp -d)
if [ -z "$TMP_DIR" ]; then exit 1; fi

FLAG="$TMP_DIR/flag"
mkfifo "$FLAG" || { rm -rf "$TMP_DIR"; exit 1; }

"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" genkey -s "$KEY_SIZE" -o >(cryptsetup luksFormat -q --force-password --key-slot 1 -s "$(( $KEY_SIZE * 8 ))" --master-key-file /dev/stdin "$DEVICE" <(echo -n "$TMP_PASSWORD") && : >"$FLAG") || { rm -rf "$TMP_DIR"; exit 1; }

# Wait for cryptsetup to finish:
cat "$FLAG" >/dev/null

rm -rf "$TMP_DIR"

echo "Saving the key on the card..."
UUID="$(cryptsetup luksUUID -q "$DEVICE")"

if [ -z "$UUID" ]; then exit 1; fi

"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" storekey -u "$UUID" -i <(from_hex $(cryptsetup -q --dump-master-key -d <(echo -n "$TMP_PASSWORD") luksDump "$DEVICE" | egrep -o '(\w{2} ){2,}')) || exit 1

echo "Please enter an emergency recovery passphrase in case of card loss..."
cryptsetup luksAddKey -d <(echo -n "$TMP_PASSWORD") "$DEVICE" || exit 1
cryptsetup luksKillSlot -q "$DEVICE" 1 || exit 1

echo "Successfully formated device '$DEVICE'!"
