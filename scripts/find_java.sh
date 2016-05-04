#!/bin/bash

JAVA="$(which java)"

[ -z "$JAVA" ] && exit 1

JAVA="$(readlink -f "$JAVA")"

[ -z "$JAVA" ] && exit 1

JAVA="$(dirname "$JAVA")"

[ -z "$JAVA" ] && exit 1

JAVA="$(dirname "$JAVA")"

[ -z "$JAVA" ] && exit 1

JAVA="$(dirname "$JAVA")"

[ -z "$JAVA" ] && exit 1

echo "$JAVA"