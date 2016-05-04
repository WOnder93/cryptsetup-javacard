#!/bin/bash

PROJECT_HOME="$(dirname "$0")/.."

if [ "$1" = '-?' ] || [ "$1" = '-h' ] || [ "$1" = '--help' ] || [ "$#" -lt 2 ]; then
    echo "Produce sample APDU dumps for analysis."
    echo
    echo "Usage: $0 TERMINAL_NAME DEST_DIR"
    echo
    echo "  TERMINAL_NAME -- the name of the JavaCard terminal to use"
    echo "  DEST_DIR      -- the destination directory for the dumps"
    exit 0
fi
TERMINAL_NAME="$1"
DEST_DIR="$2"

if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME="$(bash "$PROJECT_HOME/scripts/find_java.sh")"
    if [ -z "$JAVA_HOME" ]; then
        echo "ERROR: You must set JAVA_HOME to your JDK path!" 1>&2
        echo "ERROR:   e. g. JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 $0 [...]" 1>&2
        exit 1
    fi
fi

CLIENT_PATH="$PROJECT_HOME/JCKeyStorage/dist/JCKeyStorage.jar"

mkdir -p "$DEST_DIR" || exit 1

PUBKEY_FILE="$DEST_DIR/public.key"
UUID='3f52c640-c35f-413f-b4d8-53382693cae5'

echo "NOTE: You will have to enter the master password several times (deal with it...)."

echo "Dumping public key retrieval..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_getpubkey.txt" getpubkey || exit 1

echo "Dumping key generation (128-bit key)..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_genkey_128.txt" genkey -s 16 -o /dev/null || exit 1

echo "Dumping key generation (256-bit key)..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_genkey_256.txt" genkey -s 32 -o /dev/null || exit 1

echo "Dumping key generation (512-bit key)..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_genkey_512.txt" genkey -s 64 -o /dev/null || exit 1

echo "Dumping key upload..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_storekey.txt" storekey -u "$UUID" -i <(head -c 32 /dev/urandom) || exit 1

echo "Dumping key download..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_loadkey.txt" loadkey -u "$UUID" -o /dev/null || exit 1

echo "Dumping key deletion..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_delkey.txt" delkey -u "$UUID" || exit 1

echo "Dumping password change..."
"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" -d "$DEST_DIR/dump_changepw.txt" changepw || exit 1

echo "Done!"
