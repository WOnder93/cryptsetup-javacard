#!/bin/bash

PROJECT_HOME="$(dirname "$0")/.."

if [ -z "$JAVA_HOME" ]; then
    export JAVA_HOME="$(bash "$PROJECT_HOME/scripts/find_java.sh")"
    if [ -z "$JAVA_HOME" ]; then
        echo "ERROR: You must set JAVA_HOME to your JDK path!" 1>&2
        echo "ERROR:   e. g. JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 $0 [...]" 1>&2
        exit 1
    fi
fi

"$JAVA_HOME/bin/java" -jar "$PROJECT_HOME/ext/gp.jar" --all -d 2>/dev/null | egrep '^\[[ *]\]'