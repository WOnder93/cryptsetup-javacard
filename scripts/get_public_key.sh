#!/bin/bash

PROJECT_HOME="$(dirname "$0")/.."

if [ "$1" = '-?' ] || [ "$1" = '-h' ] || [ "$1" = '--help' ] || [ "$#" -lt 2 ]; then
    echo "Get the public key."
    echo
    echo "Usage: $0 PUBKEY_FILE TERMINAL_NAME"
    echo
    echo "  PUBKEY_FILE   -- the file containing the card's public key"
    echo "  TERMINAL_NAME -- the name of the JavaCard terminal to use"
    exit 0
fi
PUBKEY_FILE="$1"
TERMINAL_NAME="$2"

if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME="$(bash "$PROJECT_HOME/scripts/find_java.sh")"
    if [ -z "$JAVA_HOME" ]; then
        echo "ERROR: You must set JAVA_HOME to your JDK path!" 1>&2
        echo "ERROR:   e. g. JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 $0 [...]" 1>&2
        exit 1
    fi
fi

CLIENT_PATH="$PROJECT_HOME/JCKeyStorage/dist/JCKeyStorage.jar"

"$JAVA_HOME/bin/java" -jar "$CLIENT_PATH" -p "$PUBKEY_FILE" -t "$TERMINAL_NAME" getpubkey || exit 1

echo "Public key has been loaded successfully!"