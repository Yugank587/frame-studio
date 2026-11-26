@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo The local image-processing environment is not installed.
  echo Run: uv venv --python 3.13 .venv
  echo Then: uv pip install --python .venv\Scripts\python.exe -r requirements.txt
  pause
  exit /b 1
)
echo Keep this window open while you use Frame Studio.
".venv\Scripts\python.exe" main.py
pause
