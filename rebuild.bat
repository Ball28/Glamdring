@echo off
echo ===================================================
echo   Rebuilding Glamdring.exe... 🔨
echo ===================================================
pip install pyinstaller
pip install uvicorn
pip install pydantic
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
