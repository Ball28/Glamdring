@echo off
echo ===================================================
echo   Rebuilding Glamdring.exe... 🔨
echo ===================================================

pip install pyinstaller pywin32
pip install -r requirements.txt 
pyinstaller --onefile --add-data "backend/config.py;backend" --hidden-import=config malware_analyzer.py
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
