import PyInstaller.__main__
import os
import shutil

# Clean previous build with retry logic
def remove_readonly(func, path, _):
    """Clear the readonly bit and reattempt the removal"""
    os.chmod(path, 0o777)
    func(path)

def clean_build_dirs():
    """Clean build directories with retries"""
    for folder in ["build", "dist"]:
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder, onerror=remove_readonly)
            except PermissionError:
                print(f"⚠️  Warning: Could not delete {folder}. Please close Glamdring.exe and try again.")
                input("Press Enter after closing the program...")
                shutil.rmtree(folder, onerror=remove_readonly)

clean_build_dirs()

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
    
    # Include entire backend folder (includes config.py and other files)
    '--add-data=backend;backend',
    
    # Hidden Imports (sometimes missed by analysis)
    '--hidden-import=pydantic_settings',
    '--hidden-import=sqlalchemy',
    '--hidden-import=sqlalchemy.ext.declarative',
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