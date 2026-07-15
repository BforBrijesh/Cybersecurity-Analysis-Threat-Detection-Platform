@echo off
title CyberShield AI
echo.
echo  ============================================
echo   CyberShield AI - KANAD S.H.I.E.L.D 2026
echo  ============================================
echo.
echo  Starting on http://localhost:8501
echo  Press Ctrl+C to stop
echo.
C:\Users\BRIJESH\AppData\Local\Programs\Python\Python311\python.exe -m streamlit run app.py --server.port 8501 --server.headless false --browser.gatherUsageStats false
pause
