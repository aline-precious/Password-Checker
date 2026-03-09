#!/bin/bash
# CIPHER — Build and Run Java CLI
# Requires: Java JDK 11+

DIR="$(dirname "$0")/java-cli"
cd "$DIR"

echo ""
echo "  🔨  Compiling Java CLI..."
mkdir -p out
javac -d out src/*.java

if [ $? -ne 0 ]; then
  echo "  ❌  Compilation failed. Make sure JDK (not just JRE) is installed."
  echo "      Ubuntu/Debian: sudo apt install default-jdk"
  echo "      macOS:         brew install openjdk"
  exit 1
fi

echo "  ✔   Compiled successfully."
echo ""

if [ "$#" -gt 0 ]; then
  # Batch mode
  java -cp out PasswordChecker "$@"
else
  # Interactive
  java -cp out PasswordChecker
fi
