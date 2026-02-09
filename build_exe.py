import PyInstaller.__main__
import os
import shutil

# Clean previous build
if os.path.exists("build"):
    shutil.rmtree("build")
if os.path.exists("dist"):
    shutil.rmtree("dist")

# PyInstaller Arguments
args = [
    'malware_analyzer.py',  # Entry Point
    '--name=Glamdring',
    '--onefile',
    '--clean',
    
    # Include backend package
    '--paths=.',
    
    # Include Static Files (HTML/JS/CSS)
    '--add-data=static;static',
    
    # Include Default Rules (if they exist in backend)
    '--add-data=backend/default_rules.yar;backend',
    
    # Hidden Imports (sometimes missed by analysis)
    '--hidden-import=uvicorn.logging',
    '--hidden-import=uvicorn.loops',
    '--hidden-import=uvicorn.loops.auto',
    '--hidden-import=uvicorn.protocols',
    '--hidden-import=uvicorn.protocols.http',
    '--hidden-import=uvicorn.protocols.http.auto',
    '--hidden-import=uvicorn.lifespan',
    '--hidden-import=uvicorn.lifespan.on',
    '--hidden-import=engineio.async_drivers.asgi',
    '--hidden-import=sqlalchemy.sql.default_comparator',
]

print("🔨 Building Glamdring.exe ...")
PyInstaller.__main__.run(args)
print("✅ Build Complete! Check dist/Glamdring.exe")
