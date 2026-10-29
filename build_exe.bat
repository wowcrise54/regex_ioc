@echo off
rem Build IoCExtractor.exe (single file, no console) into dist\
rem (ASCII only: cmd.exe misreads UTF-8 batch files)
setlocal
cd /d "%~dp0"

if not exist .venv (
    python -m venv .venv || goto :error
)
call .venv\Scripts\activate.bat || goto :error
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt pyinstaller || goto :error

pyinstaller --noconfirm --clean --onefile --windowed ^
    --name IoCExtractor ^
    --exclude-module numpy --exclude-module PIL --exclude-module pytest ^
    main.py || goto :error

echo.
echo Done: %~dp0dist\IoCExtractor.exe
exit /b 0

:error
echo Build failed.
exit /b 1
