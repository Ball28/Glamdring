@echo off
echo ===================================================
echo   Rebuilding Glamdring.exe... 🔨
echo ===================================================

pip install https://github.com/pyinstaller/pyinstaller/tarball/develop
pip install -r requirements.txt 

python build_exe.py

echo.
echo ===================================================
if %ERRORLEVEL% EQU 0 (
    echo   ✅ Build Successful! Check dist\Glamdring.exe
) else (
    echo   ❌ Build Failed! Check errors above.
)
echo ===================================================
pause
