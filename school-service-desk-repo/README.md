# School Service Desk (ระบบแจ้งซ่อมโรงเรียน)
- `backend/`  Node.js + Express + PostgreSQL (deploy บน Render, ฐานข้อมูลบน Neon)
- `frontend/` เว็บ static (deploy บน Vercel) — แก้ `frontend/config.js` ให้ชี้ไปที่ URL ของ backend

ตัวแปรของ backend: `DATABASE_URL`, `JWT_SECRET`, `CORS_ORIGIN` (URL ของ Vercel), `SEED_PASSWORD`
บัญชีตั้งต้น: teacher1, staff1, staff2, admin1 (รหัสผ่านตาม `SEED_PASSWORD`)
