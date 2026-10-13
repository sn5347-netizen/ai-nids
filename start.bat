@echo off
title AI-Powered Network Intrusion Detection System
echo ============================================================
echo   CYBERSHIELD: AI-POWERED NETWORK INTRUSION DETECTION SYSTEM
echo ============================================================
echo.
echo Starting Backend (FastAPI on http://127.0.0.1:8000)...
start "AI-NIDS Backend" cmd /k "cd /d %~dp0backend && ..\venv\Scripts\activate && uvicorn app.main:app --reload --port 8000"

echo Starting Frontend (Vite React on http://localhost:5173)...
start "AI-NIDS Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo Both servers are launching!
echo Backend API Docs: http://127.0.0.1:8000/docs
echo SOC Dashboard:    http://localhost:5173
echo.
pause

