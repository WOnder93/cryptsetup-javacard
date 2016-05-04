#!/bin/bash

PROJECT_HOME="$(dirname "$0")/.."

(cd "$PROJECT_HOME/JCKeyStorage"; ant jar -q)