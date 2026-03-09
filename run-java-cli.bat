@echo off
echo.
echo   CIPHER - Building Java CLI
echo   ============================
echo.
cd /d "%~dp0java-cli"
if not exist out mkdir out
javac -d out src\*.java
if errorlevel 1 (
  echo   Compilation failed. Install JDK: https://adoptium.net
  pause
  exit /b 1
)
echo   Build successful.
echo.
java -cp out PasswordChecker %*
pause
