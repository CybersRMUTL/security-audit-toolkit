#!/bin/bash
#
# unlock-macos.command — RMUT CERT Security Audit Toolkit
# ----------------------------------------------------------------------------
# ปลดล็อก macOS Gatekeeper / Quarantine ให้ "Security Audit Toolkit.app"
# แล้วเปิดโปรแกรมให้อัตโนมัติ (ทำครั้งแรกครั้งเดียว)
#
# ⚠️ สำคัญบน macOS 15 (Sequoia) ขึ้นไป:
#    การ "ดับเบิลคลิก" ไฟล์ .command นี้จะถูก Gatekeeper บล็อก (เพราะไฟล์เอง
#    ก็ติดธง quarantine จากการดาวน์โหลด) — ให้รันผ่าน Terminal แทน:
#
#        bash <ลากไฟล์นี้มาวาง>
#
#    หรือจะรันคำสั่งเดียวตรง ๆ ก็ได้ (ไม่ต้องใช้ไฟล์นี้เลย):
#
#        xattr -cr "<โฟลเดอร์ที่แตก zip>" && open "<โฟลเดอร์ที่แตก zip>"
# ----------------------------------------------------------------------------
set -euo pipefail

echo "================================================================="
echo " 🛡️  RMUT CERT — ปลดล็อก macOS Security / Gatekeeper"
echo "================================================================="
echo ""

# โฟลเดอร์ที่ไฟล์สคริปต์นี้วางอยู่ (= โฟลเดอร์ที่แตก zip)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ค้นหาแอปข้าง ๆ สคริปต์ ถ้าไม่เจอให้ลองใน /Applications
APP=""
if [ -d "$DIR/Security Audit Toolkit.app" ]; then
    APP="$DIR/Security Audit Toolkit.app"
elif [ -d "/Applications/Security Audit Toolkit.app" ]; then
    APP="/Applications/Security Audit Toolkit.app"
fi

echo "[*] กำลังลบธงกักกัน (com.apple.quarantine) ของทุกไฟล์ในโฟลเดอร์นี้..."
# -c ล้าง extended attributes ทั้งหมด, -r ทำซ้ำทุกไฟล์ย่อย; กันพังด้วย || true
xattr -cr "$DIR" 2>/dev/null || true

if [ -n "$APP" ]; then
    xattr -cr "$APP" 2>/dev/null || true
    echo ""
    echo "================================================================="
    echo " ✅ ปลดล็อกสำเร็จ! กำลังเปิดโปรแกรม..."
    echo "================================================================="
    open "$APP"
else
    echo ""
    echo "✅ ปลดล็อกไฟล์ในโฟลเดอร์นี้เรียบร้อยแล้ว"
    echo "   ไม่พบ 'Security Audit Toolkit.app' ข้าง ๆ สคริปต์หรือใน /Applications"
    echo "   ให้ดับเบิลคลิกเปิดแอปได้เลย"
fi

echo ""
# หยุดรอเมื่อเปิดด้วยการดับเบิลคลิก (มี TTY) เพื่อให้อ่านข้อความทัน
if [ -t 0 ]; then
    read -r -p "กด Enter เพื่อปิดหน้าต่างนี้..." _ || true
fi
