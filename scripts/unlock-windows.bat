@echo off
rem ============================================================================
rem unlock-windows.bat - RMUT CERT Security Audit Toolkit
rem ----------------------------------------------------------------------------
rem ปลดล็อก "Mark of the Web" (ธงไฟล์ที่ดาวน์โหลดจากอินเทอร์เน็ต) ของทุกไฟล์
rem ในโฟลเดอร์นี้ แล้วเปิด Security_Audit_Toolkit.exe ให้อัตโนมัติ
rem ดับเบิลคลิกไฟล์นี้ได้เลย (ถ้า Windows ถามสิทธิ์ ให้กด Run / More info > Run anyway)
rem ============================================================================
chcp 65001 >nul
cd /d "%~dp0"

echo =====================================================================
echo   RMUT CERT - ปลดล็อก Windows Security (Mark of the Web)
echo =====================================================================
echo.
echo [*] กำลังปลดล็อกไฟล์ทั้งหมดในโฟลเดอร์นี้...

powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse -File | Unblock-File" 2>nul

echo [OK] ปลดล็อกเรียบร้อยแล้ว
echo.

if exist "%~dp0Security_Audit_Toolkit.exe" (
    echo [*] กำลังเปิดโปรแกรม Security_Audit_Toolkit.exe ...
    start "" "%~dp0Security_Audit_Toolkit.exe"
) else (
    echo [!] ไม่พบ Security_Audit_Toolkit.exe ในโฟลเดอร์นี้ - ให้ดับเบิลคลิกเปิดเองได้เลย
)

echo.
pause
