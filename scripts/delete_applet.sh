#!/bin/bash

if [ "$1" = '-?' ] || [ "$1" = '-h' ] || [ "$1" = '--help' ]; then
    echo "Delete applet from a card."
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

APPLET_PACKAGE_AID='4a434b6579706b67'
APPLET_AID='4a434b657953746f72616765'

"$JAVA_HOME/bin/java" -jar "$PROJECT_HOME/ext/gp.jar" --delete "$APPLET_AID" "$@"

"$JAVA_HOME/bin/java" -jar "$PROJECT_HOME/ext/gp.jar" --delete "$APPLET_PACKAGE_AID" "$@"

echo "Applet has been deleted successfully!"