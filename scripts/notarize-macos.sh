#!/bin/bash
#
# notarize-macos.sh — RMUT CERT Security Audit Toolkit
# ============================================================================
# เซ็น (codesign) + ส่ง notarize + ปิดผนึก (staple) ให้ "Security Audit
# Toolkit.app" — เป็น "วิธีเดียว" ที่ทำให้ผู้ใช้ "ดับเบิลคลิกเปิดได้เลย"
# โดยไม่มีคำเตือน Gatekeeper อีกต่อไป (ถาวร).
#
# ⚙️ ต้องเตรียมครั้งเดียว (ของผู้ build เท่านั้น ไม่เกี่ยวกับผู้ใช้ปลายทาง):
#   1) สมัคร Apple Developer Program ($99/ปี) → https://developer.apple.com
#   2) สร้าง/ดาวน์โหลด "Developer ID Application" certificate ลง Keychain
#      (Xcode > Settings > Accounts > Manage Certificates > + > Developer ID)
#   3) สร้าง app-specific password ที่ https://appleid.apple.com (Security)
#      แล้วบันทึกเป็น keychain profile ของ notarytool (ทำครั้งเดียว):
#
#        xcrun notarytool store-credentials "RMUT_NOTARY" \
#          --apple-id "you@example.com" \
#          --team-id  "TEAMID1234" \
#          --password "xxxx-xxxx-xxxx-xxxx"
#
# ▶️ วิธีใช้:
#        ./scripts/notarize-macos.sh "/path/to/Security Audit Toolkit.app"
# ============================================================================
set -euo pipefail

# ---- แก้ 3 ค่านี้ให้ตรงกับบัญชี/ใบรับรองของคุณ ----------------------------
SIGN_IDENTITY="Developer ID Application: YOUR NAME (TEAMID1234)"  # ชื่อ cert ใน Keychain
NOTARY_PROFILE="RMUT_NOTARY"                                      # ชื่อ profile ที่ store-credentials ไว้
ENTITLEMENTS=""   # (ไม่บังคับ) path ไปยัง .entitlements ถ้าต้องการ hardened runtime แบบกำหนดเอง
# ---------------------------------------------------------------------------

APP="${1:-}"
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
    echo "❌ ใช้: $0 \"/path/to/Security Audit Toolkit.app\"" >&2
    exit 1
fi

echo "==> [1/4] codesign (hardened runtime, --deep) : $APP"
CODESIGN_ARGS=(--force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY")
[ -n "$ENTITLEMENTS" ] && CODESIGN_ARGS+=(--entitlements "$ENTITLEMENTS")
codesign "${CODESIGN_ARGS[@]}" "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "==> [2/4] zip แอปสำหรับส่ง notarize"
WORKZIP="$(mktemp -d)/app.zip"
/usr/bin/ditto -c -k --keepParent "$APP" "$WORKZIP"

echo "==> [3/4] ส่ง notarize แล้วรอผล (อาจใช้เวลาหลายนาที)"
xcrun notarytool submit "$WORKZIP" --keychain-profile "$NOTARY_PROFILE" --wait

echo "==> [4/4] staple ผลการ notarize ลงในแอป"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo ""
echo "✅ เสร็จสมบูรณ์ — ตอนนี้ '$APP' เปิดได้ด้วยดับเบิลคลิกโดยไม่มีคำเตือน Gatekeeper"
echo "   นำไป zip แจกจ่ายได้เลย (ไฟล์ที่ staple แล้วเปิดได้แม้เครื่องผู้ใช้ออฟไลน์)"
