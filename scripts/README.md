# scripts/ — ตัวช่วยแจกจ่ายแอปเดสก์ท็อป (packaging helpers)

สคริปต์ในโฟลเดอร์นี้ช่วยให้ **แอปเดสก์ท็อป** (macOS `.app` / Windows `.exe`) ที่ build ออกมา เปิดใช้งานได้ง่ายขึ้น ไม่เกี่ยวกับการรันตัว CLI (`security_audit_toolkit.py`)

| ไฟล์ | สำหรับ | ทำอะไร |
|------|--------|--------|
| [`unlock-macos.command`](unlock-macos.command) | ผู้ใช้ปลายทาง (ฟรี) | ลบธง quarantine ของโฟลเดอร์ที่แตก zip แล้วเปิดแอป — **นำไปแนบในแพ็กเกจ `.zip` ของ macOS ได้** |
| [`unlock-windows.bat`](unlock-windows.bat) | ผู้ใช้ปลายทาง (ฟรี) | ปลด Mark-of-the-Web ของทุกไฟล์ในโฟลเดอร์ แล้วเปิด `.exe` — **นำไปแนบในแพ็กเกจ `.zip` ของ Windows ได้** |
| [`notarize-macos.sh`](notarize-macos.sh) | ผู้ build (ต้องมี Apple Developer) | codesign + notarize + staple ให้ `.app` → ผู้ใช้ดับเบิลคลิกเปิดได้เลย ไม่มีคำเตือน **(วิธีที่ถูกต้องถาวร)** |
| [`sign-windows.ps1`](sign-windows.ps1) | ผู้ build (ต้องมี Code Signing cert) | เซ็น Authenticode ให้ `.exe` เพื่อลด/ตัด SmartScreen |

## ทำไมถึงต้องมีสคริปต์พวกนี้

macOS และ Windows ติด **ธงกักกัน (quarantine / Mark-of-the-Web)** ให้ทุกไฟล์ที่ดาวน์โหลดจากอินเทอร์เน็ต และบล็อกไม่ให้แอปที่ "ไม่ได้เซ็น" เปิดด้วยการดับเบิลคลิก — เป็นกลไกความปลอดภัยที่ตั้งใจออกแบบไว้

- **ฟรี / ทำได้ทันที:** ลบธงกักกันเองด้วย `xattr -cr` (mac) หรือ `Unblock-File` (win) — ดูวิธีคัดลอกคำสั่งบรรทัดเดียวใน [README หลัก](../README.md#-ดาวน์โหลด-เวอร์ชันพร้อมใช้--ไม่ต้องติดตั้ง-python)
- **ถาวร (เสียเงิน):** เซ็น + notarize (mac) / code-sign (win) — เป็นวิธีเดียวที่ทำให้ "ดับเบิลคลิกเปิดได้เลย" โดยไม่มีคำเตือน

> ⚠️ บน macOS 15 (Sequoia) ขึ้นไป แม้แต่ไฟล์ `.command` ที่แนบมาก็ติดธงกักกัน จึง **ดับเบิลคลิกไม่ได้** — ต้องรันผ่าน Terminal ด้วย `bash <ลากไฟล์มาวาง>` หรือใช้คำสั่ง `xattr -cr` ตรง ๆ
