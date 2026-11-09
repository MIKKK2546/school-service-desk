-- 1) ฝ่ายที่รับผิดชอบ
CREATE TABLE IF NOT EXISTS departments (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL
);

-- 2) ผู้ใช้งาน (teacher / staff / admin)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(100) NOT NULL,
  role VARCHAR(10) NOT NULL DEFAULT 'teacher' CHECK (role IN ('teacher','staff','admin')),
  department_id INT REFERENCES departments(id),
  active BOOLEAN NOT NULL DEFAULT TRUE   -- ลบบัญชี = ตั้งเป็น false (เก็บประวัติไว้)
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;  -- สำหรับฐานข้อมูลเดิมที่สร้างไว้ก่อนหน้า

-- 3) ประเภทปัญหา
CREATE TABLE IF NOT EXISTS service_categories (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  department_id INT NOT NULL REFERENCES departments(id)
);

-- 4) เรื่องที่แจ้ง (รูปเก็บเป็นข้อความ base64 ใน image_data)
CREATE TABLE IF NOT EXISTS service_requests (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id),
  category_id INT NOT NULL REFERENCES service_categories(id),
  location VARCHAR(100) NOT NULL,
  description TEXT NOT NULL,
  image_data TEXT,
  status VARCHAR(12) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_progress','completed')),
  assigned_to INT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_requests_status ON service_requests(status);

-- 5) ประวัติการเปลี่ยนสถานะ
CREATE TABLE IF NOT EXISTS request_updates (
  id SERIAL PRIMARY KEY,
  request_id INT NOT NULL REFERENCES service_requests(id),
  updated_by INT NOT NULL REFERENCES users(id),
  new_status VARCHAR(12) NOT NULL CHECK (new_status IN ('pending','in_progress','completed')),
  note TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
