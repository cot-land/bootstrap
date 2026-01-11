@echo off
REM Windows test runner wrapper - calls PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0run_tests_windows.ps1"
