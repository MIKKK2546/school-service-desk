const fs = require('fs'), path = require('path');
const express = require('express'), cors = require('cors'), { Pool } = require('pg');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');

const { DATABASE_URL, JWT_SECRET, CORS_ORIGIN, SEED_PASSWORD } = process.env;
if (!DATABASE_URL || !JWT_SECRET) { console.error('ต้องตั้งค่า DATABASE_URL และ JWT_SECRET'); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL }); // Neon URL มี ?sslmode=require อยู่แล้ว
const ST = ['pending', 'in_progress', 'completed'];
const app = express();
app.use(cors({ origin: CORS_ORIGIN ? CORS_ORIGIN.split(',').map(s => s.trim()) : true }));
app.use(express.json({ limit: '1mb' }));

const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' }); });
const auth = roles => async (req, res, next) => {
  try { req.u = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); }
  catch { return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' }); }
  try {   // ตรวจทุกครั้งว่าบัญชียังใช้งานได้ และใช้บทบาทล่าสุดจากฐานข้อมูล
    const me = (await pool.query('SELECT role,active FROM users WHERE id=$1', [req.u.id])).rows[0];
    if (!me || !me.active) return res.status(401).json({ error: 'บัญชีนี้ใช้งานไม่ได้ กรุณาเข้าสู่ระบบใหม่' });
    req.u.role = me.role;
  } catch (e) { console.error(e); return res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' }); }
  if (roles && !roles.includes(req.u.role)) return res.status(403).json({ error: 'ไม่มีสิทธิ์เข้าถึง' });
  next();
};
const token = u => jwt.sign({ id: u.id, name: u.full_name, role: u.role }, JWT_SECRET, { expiresIn: '8h' });

app.param('id', (req, res, next, val) => Number.isInteger(+val) ? next() : res.status(400).json({ error: 'เลขที่ไม่ถูกต้อง' }));

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/register', wrap(async (req, res) => {
  const { full_name, username, password } = req.body;
  if (!(full_name || '').trim() || !(username || '').trim() || (password || '').length < 6)
    return res.status(400).json({ error: 'กรอกให้ครบ และรหัสผ่านอย่างน้อย 6 ตัวอักษร' });
  const r = await pool.query(
    "INSERT INTO users(username,password_hash,full_name,role) VALUES($1,$2,$3,'teacher') ON CONFLICT (username) DO NOTHING RETURNING id",
    [username.trim(), await bcrypt.hash(password, 10), full_name.trim()]);
  if (!r.rows.length) return res.status(409).json({ error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
  res.json({ ok: true });
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  const u = (await pool.query('SELECT * FROM users WHERE username=$1 AND active', [(username || '').trim()])).rows[0];
  if (!u || !(await bcrypt.compare(password || '', u.password_hash)))
    return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  res.json({ token: token(u), user: { id: u.id, name: u.full_name, role: u.role } });
}));

app.get('/api/categories', auth(), wrap(async (req, res) =>
  res.json((await pool.query('SELECT id,name FROM service_categories ORDER BY id')).rows)));

app.get('/api/staff', auth(['staff']), wrap(async (req, res) =>
  res.json((await pool.query("SELECT id,full_name FROM users WHERE role='staff' AND active ORDER BY id")).rows)));

// ---- ครู ----
app.post('/api/requests', auth(['teacher']), wrap(async (req, res) => {
  const { category_id, location, description, image_data } = req.body, img = image_data || null;
  if (!+category_id || !(location || '').trim() || !(description || '').trim())
    return res.status(400).json({ error: 'กรุณากรอกห้องและอาการให้ครบ' });
  if (img && (img.length > 900000 || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(img)))
    return res.status(400).json({ error: 'รูปไม่ถูกต้องหรือใหญ่เกินไป' });
  const id = (await pool.query(
    'INSERT INTO service_requests(user_id,category_id,location,description,image_data) VALUES($1,$2,$3,$4,$5) RETURNING id',
    [req.u.id, +category_id, location.trim(), description.trim(), img])).rows[0].id;
  await pool.query("INSERT INTO request_updates(request_id,updated_by,new_status,note) VALUES($1,$2,'pending','แจ้งเรื่อง')", [id, req.u.id]);
  res.json({ id });
}));

app.get('/api/requests/mine', auth(['teacher']), wrap(async (req, res) => {
  const r = (await pool.query(
    'SELECT r.id,c.name cat,r.location,r.description,r.image_data,r.status,r.created_at FROM service_requests r JOIN service_categories c ON c.id=r.category_id WHERE r.user_id=$1 ORDER BY r.id DESC', [req.u.id])).rows;
  const u = (await pool.query(
    'SELECT ru.request_id,ru.new_status,ru.note,ru.updated_at,x.full_name FROM request_updates ru JOIN users x ON x.id=ru.updated_by WHERE ru.request_id=ANY($1) ORDER BY ru.id', [r.map(x => x.id)])).rows;
  r.forEach(x => x.log = u.filter(l => l.request_id === x.id));
  res.json(r);
}));

// ---- เจ้าหน้าที่ ----
app.get('/api/requests', auth(['staff', 'admin']), wrap(async (req, res) => {
  const f = ST.includes(req.query.status) ? req.query.status : null;
  res.json((await pool.query(
    `SELECT r.id,r.location,r.status,r.created_at,c.name cat,u.full_name FROM service_requests r
     JOIN service_categories c ON c.id=r.category_id JOIN users u ON u.id=r.user_id
     WHERE ($1::text IS NULL OR r.status=$1) ORDER BY r.id DESC`, [f])).rows);
}));

app.get('/api/requests/:id', auth(['staff', 'admin']), wrap(async (req, res) => {
  const id = +req.params.id;
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'เลขที่ไม่ถูกต้อง' });
  const r = (await pool.query(
    'SELECT r.id,r.location,r.description,r.image_data,r.status,r.assigned_to,c.name cat,u.full_name reporter,a.full_name assignee FROM service_requests r JOIN service_categories c ON c.id=r.category_id JOIN users u ON u.id=r.user_id LEFT JOIN users a ON a.id=r.assigned_to WHERE r.id=$1', [id])).rows[0];
  if (!r) return res.status(404).json({ error: 'ไม่พบรายการ' });
  r.log = (await pool.query(
    'SELECT ru.new_status,ru.note,ru.updated_at,x.full_name FROM request_updates ru JOIN users x ON x.id=ru.updated_by WHERE ru.request_id=$1 ORDER BY ru.id', [id])).rows;
  res.json(r);
}));

app.patch('/api/requests/:id', auth(['staff']), wrap(async (req, res) => {
  const id = +req.params.id, { status, assigned_to, note } = req.body;
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'เลขที่ไม่ถูกต้อง' });
  const cur = (await pool.query('SELECT status FROM service_requests WHERE id=$1', [id])).rows[0];
  if (!cur) return res.status(404).json({ error: 'ไม่พบรายการ' });
  if (cur.status === 'completed') return res.status(409).json({ error: 'งานนี้ดำเนินการเสร็จแล้ว ไม่สามารถแก้ไขได้อีก' });
  const as = +assigned_to || null;
  let st = ST.includes(status) ? status : cur.status;
  if (st === 'pending' && as) st = 'in_progress';
  if (ST.indexOf(st) <= ST.indexOf(cur.status)) return res.status(409).json({ error: 'สถานะนี้อัปเดตไปแล้ว กรุณาเลือกสถานะถัดไป' });
  // กันกดซ้ำ/ส่งซ้ำพร้อมกัน: อัปเดตได้เฉพาะเมื่อสถานะยังเป็นค่าเดิม
  const up = await pool.query('UPDATE service_requests SET status=$1, assigned_to=$2 WHERE id=$3 AND status=$4 RETURNING id', [st, as, id, cur.status]);
  if (!up.rows.length) return res.status(409).json({ error: 'เรื่องนี้ถูกอัปเดตไปแล้ว กรุณารีเฟรชหน้า' });
  await pool.query('INSERT INTO request_updates(request_id,updated_by,new_status,note) VALUES($1,$2,$3,$4)',
    [id, req.u.id, st, (note || '').trim() || 'อัปเดตสถานะ']);
  res.json({ ok: true });
}));

// ---- ผู้ดูแลระบบ ----
app.get('/api/admin/summary', auth(['admin']), wrap(async (req, res) => {
  const counts = (await pool.query('SELECT status, COUNT(*)::int t FROM service_requests GROUP BY status')).rows;
  const history = (await pool.query(
    `SELECT ru.updated_at,ru.new_status,r.id rid,c.name cat,x.full_name by_name FROM request_updates ru
     JOIN service_requests r ON r.id=ru.request_id JOIN service_categories c ON c.id=r.category_id
     JOIN users x ON x.id=ru.updated_by ORDER BY ru.id DESC LIMIT 100`)).rows;
  res.json({ counts, history });
}));

// ---- ผู้ดูแลระบบ: ฝ่ายและประเภทปัญหา ----
const nm = x => (x || '').trim();
app.get('/api/admin/catalog', auth(['admin']), wrap(async (req, res) => res.json({
  departments: (await pool.query('SELECT id,name FROM departments ORDER BY id')).rows,
  categories: (await pool.query('SELECT id,name,department_id FROM service_categories ORDER BY id')).rows })));

app.post('/api/admin/departments', auth(['admin']), wrap(async (req, res) => {
  if (!nm(req.body.name)) return res.status(400).json({ error: 'กรุณากรอกชื่อฝ่าย' });
  await pool.query('INSERT INTO departments(name) VALUES($1)', [nm(req.body.name)]);
  res.json({ ok: true });
}));
app.patch('/api/admin/departments/:id', auth(['admin']), wrap(async (req, res) => {
  if (!nm(req.body.name)) return res.status(400).json({ error: 'กรุณากรอกชื่อฝ่าย' });
  const r = await pool.query('UPDATE departments SET name=$1 WHERE id=$2 RETURNING id', [nm(req.body.name), +req.params.id]);
  if (!r.rows.length) return res.status(404).json({ error: 'ไม่พบฝ่าย' });
  res.json({ ok: true });
}));
app.delete('/api/admin/departments/:id', auth(['admin']), wrap(async (req, res) => {
  const id = +req.params.id;
  const used = (await pool.query("SELECT (SELECT COUNT(*) FROM service_categories WHERE department_id=$1)::int c, (SELECT COUNT(*) FROM users WHERE department_id=$1 AND active)::int u", [id])).rows[0];
  if (used.c || used.u) return res.status(409).json({ error: 'ฝ่ายนี้ยังมีประเภทปัญหาหรือเจ้าหน้าที่สังกัดอยู่ ลบไม่ได้' });
  await pool.query('UPDATE users SET department_id=NULL WHERE department_id=$1', [id]);
  const r = await pool.query('DELETE FROM departments WHERE id=$1 RETURNING id', [id]);
  if (!r.rows.length) return res.status(404).json({ error: 'ไม่พบฝ่าย' });
  res.json({ ok: true });
}));

app.post('/api/admin/categories', auth(['admin']), wrap(async (req, res) => {
  const d = await pool.query('SELECT 1 FROM departments WHERE id=$1', [+req.body.department_id || 0]);
  if (!nm(req.body.name) || !d.rows.length) return res.status(400).json({ error: 'กรุณากรอกชื่อและเลือกฝ่าย' });
  await pool.query('INSERT INTO service_categories(name,department_id) VALUES($1,$2)', [nm(req.body.name), +req.body.department_id]);
  res.json({ ok: true });
}));
app.patch('/api/admin/categories/:id', auth(['admin']), wrap(async (req, res) => {
  const dep = +req.body.department_id || null;
  if (dep && !(await pool.query('SELECT 1 FROM departments WHERE id=$1', [dep])).rows.length) return res.status(400).json({ error: 'ไม่พบฝ่าย' });
  const r = await pool.query('UPDATE service_categories SET name=COALESCE($1,name), department_id=COALESCE($2,department_id) WHERE id=$3 RETURNING id', [nm(req.body.name) || null, dep, +req.params.id]);
  if (!r.rows.length) return res.status(404).json({ error: 'ไม่พบประเภท' });
  res.json({ ok: true });
}));
app.delete('/api/admin/categories/:id', auth(['admin']), wrap(async (req, res) => {
  const id = +req.params.id;
  if ((await pool.query('SELECT 1 FROM service_requests WHERE category_id=$1 LIMIT 1', [id])).rows.length)
    return res.status(409).json({ error: 'ประเภทนี้ถูกใช้ในรายการแจ้งแล้ว ลบไม่ได้' });
  const r = await pool.query('DELETE FROM service_categories WHERE id=$1 RETURNING id', [id]);
  if (!r.rows.length) return res.status(404).json({ error: 'ไม่พบประเภท' });
  res.json({ ok: true });
}));

// ---- ผู้ดูแลระบบ: บัญชีผู้ใช้ (ลบ = ปิดการใช้งาน เพื่อเก็บประวัติการทำงานไว้) ----
app.get('/api/admin/users', auth(['admin']), wrap(async (req, res) => res.json((await pool.query(
  `SELECT u.id,u.username,u.full_name,u.role,u.department_id,d.name dept FROM users u LEFT JOIN departments d ON d.id=u.department_id
   WHERE u.active ORDER BY CASE u.role WHEN 'admin' THEN 0 WHEN 'staff' THEN 1 ELSE 2 END, u.id`)).rows)));

app.post('/api/admin/users', auth(['admin']), wrap(async (req, res) => {
  const { full_name, username, password, department_id } = req.body, dep = +department_id || null;
  if (!nm(full_name) || !nm(username) || (password || '').length < 6)
    return res.status(400).json({ error: 'กรอกให้ครบ และรหัสผ่านอย่างน้อย 6 ตัวอักษร' });
  if (dep && !(await pool.query('SELECT 1 FROM departments WHERE id=$1', [dep])).rows.length) return res.status(400).json({ error: 'ไม่พบฝ่าย' });
  const r = await pool.query(
    "INSERT INTO users(username,password_hash,full_name,role,department_id) VALUES($1,$2,$3,'staff',$4) ON CONFLICT (username) DO NOTHING RETURNING id",
    [nm(username), await bcrypt.hash(password, 10), nm(full_name), dep]);
  if (!r.rows.length) return res.status(409).json({ error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
  res.json({ ok: true });
}));

app.post('/api/admin/users/:id/password', auth(['admin']), wrap(async (req, res) => {
  if ((req.body.password || '').length < 6) return res.status(400).json({ error: 'รหัสผ่านอย่างน้อย 6 ตัวอักษร' });
  const r = await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2 AND active RETURNING id', [await bcrypt.hash(req.body.password, 10), +req.params.id]);
  if (!r.rows.length) return res.status(404).json({ error: 'ไม่พบบัญชี' });
  res.json({ ok: true });
}));

app.delete('/api/admin/users/:id', auth(['admin']), wrap(async (req, res) => {
  const id = +req.params.id;
  if (id === req.u.id) return res.status(400).json({ error: 'ลบบัญชีของตัวเองไม่ได้' });
  const u = (await pool.query('SELECT role FROM users WHERE id=$1 AND active', [id])).rows[0];
  if (!u) return res.status(404).json({ error: 'ไม่พบบัญชี' });
  if (u.role === 'admin') return res.status(400).json({ error: 'ลบบัญชีผู้ดูแลระบบไม่ได้' });
  await pool.query('UPDATE users SET active=false WHERE id=$1', [id]);
  // งานที่ยังไม่เสร็จของเจ้าหน้าที่คนนี้ กลับไปเป็น "ยังไม่มอบหมาย"
  await pool.query("UPDATE service_requests SET assigned_to=NULL WHERE assigned_to=$1 AND status<>'completed'", [id]);
  res.json({ ok: true });
}));

// ---- สร้างตาราง + ข้อมูลตั้งต้น (ทำอัตโนมัติตอนเริ่มเซิร์ฟเวอร์) ----
async function init() {
  await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
  if ((await pool.query('SELECT COUNT(*)::int n FROM users')).rows[0].n) return;
  const h = await bcrypt.hash(SEED_PASSWORD || 'ChangeMe1234', 10);
  await pool.query("INSERT INTO departments(name) VALUES('ฝ่ายไอที'),('ฝ่ายอาคารสถานที่')");
  await pool.query("INSERT INTO service_categories(name,department_id) VALUES('แจ้งซ่อมคอมพิวเตอร์',1),('หลอดไฟเสีย',2),('แอร์ไม่เย็น',2),('โต๊ะ/เก้าอี้พัง',2),('ห้องน้ำชำรุด',2)");
  await pool.query(
    "INSERT INTO users(username,password_hash,full_name,role,department_id) VALUES('teacher1',$1,'ครูสมชาย ใจดี','teacher',NULL),('staff1',$1,'ครูสมศักดิ์ (ฝ่ายไอที)','staff',1),('staff2',$1,'ช่างวิชัย (ฝ่ายอาคาร)','staff',2),('admin1',$1,'ผู้ดูแลระบบ','admin',NULL)", [h]);
  console.log('สร้างข้อมูลตั้งต้นแล้ว');
}
init().then(() => app.listen(process.env.PORT || 3000, () => console.log('API พร้อมใช้งาน')))
  .catch(e => { console.error(e); process.exit(1); });
