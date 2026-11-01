# sign-windows.ps1 — RMUT CERT Security Audit Toolkit
# ============================================================================
# เซ็นดิจิทัล (Authenticode) ให้ Security_Audit_Toolkit.exe เพื่อ "ตัด
# SmartScreen" ครั้งแรก และทำให้ผู้ใช้ "ดับเบิลคลิกเปิดได้เลย".
#
# ⚙️ ต้องมี Code Signing Certificate (OV ~$200-400/ปี หรือ EV ตัด SmartScreen
#    ได้เร็วกว่า) จาก CA เช่น DigiCert / Sectigo / SSL.com เป็นไฟล์ .pfx
#    (หรือ EV cert บน USB token). ไม่มีใบรับรอง = SmartScreen ครั้งแรกตัดไม่ได้.
#
# ▶️ วิธีใช้ (PowerShell):
#       .\scripts\sign-windows.ps1 -Exe ".\dist\Security_Audit_Toolkit.exe" `
#                                  -Pfx "C:\path\cert.pfx"
# ============================================================================
param(
    [Parameter(Mandatory = $true)] [string]$Exe,
    [Parameter(Mandatory = $true)] [string]$Pfx,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Exe)) { throw "ไม่พบไฟล์ .exe: $Exe" }
if (-not (Test-Path $Pfx)) { throw "ไม่พบไฟล์ใบรับรอง .pfx: $Pfx" }

# signtool อยู่ใน Windows SDK (เช่น C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe)
$signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source
if (-not $signtool) {
    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" |
                Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $signtool) { throw "ไม่พบ signtool.exe — ติดตั้ง Windows SDK ก่อน" }

$pwd = Read-Host "ใส่รหัสผ่านของไฟล์ .pfx" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))

Write-Host "==> กำลังเซ็น $Exe ..."
& $signtool sign /fd SHA256 /f $Pfx /p $plain /tr $TimestampUrl /td SHA256 /v $Exe

Write-Host "==> ตรวจสอบลายเซ็น ..."
& $signtool verify /pa /v $Exe

Write-Host "`n✅ เซ็นเรียบร้อย — นำ .exe ไปแจกจ่ายได้ (SmartScreen จะลดคำเตือนลงตามชื่อเสียงของใบรับรอง)"
