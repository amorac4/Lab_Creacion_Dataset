@echo off
setlocal
cd /d "%~dp0"

if exist ".env" (
  for /f "usebackq eol=# tokens=1,* delims==" %%a in (".env") do (
    if not "%%a"=="" set "%%a=%%b"
  )
)

if "%VIRUSHARE_INTERVAL_SECONDS%"=="" set "VIRUSHARE_INTERVAL_SECONDS=16"

docker build -f Dockerfile.lab -t lab-creacion-dataset:local .

docker rm -f lab-creacion-dataset-ui >nul 2>nul
docker run --name lab-creacion-dataset-ui ^
  -p 8000:8000 ^
  -e "VIRUSHARE_API_KEY=%VIRUSHARE_API_KEY%" ^
  -e "VIRUSHARE_INTERVAL_SECONDS=%VIRUSHARE_INTERVAL_SECONDS%" ^
  -e "VIRUSHARE_URL_TEMPLATE=%VIRUSHARE_URL_TEMPLATE%" ^
  -v "%cd%\data:/lab/data" ^
  lab-creacion-dataset:local
