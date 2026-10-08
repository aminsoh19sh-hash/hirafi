require('dotenv').config();
const express = require('express'), crypto = require('crypto'), os = require('os');
const { load, save, id, log } = require('./src/db');
const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(express.static('public'));

/* ---------- Security helpers ---------- */
const SECRET = process.env.SECRET || 'dev';
if (SECRET === 'dev') console.warn('⚠  SECRET is not set in .env — using an insecure default. Set it before going live.');

/* Constant-time string comparison (safe even when lengths differ) */
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const hmac = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const hash = p => { const s = crypto.randomBytes(8).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 32).toString('hex'); };
const same = (p, h) => {
  try {
    const [s, x] = String(h).split(':');
    if (!s || !x) return false;
    return safeEq(x, crypto.scryptSync(p, s, 32).toString('hex'));
  } catch { return false; }
};
const sign = (r, i) => {
  const p = Buffer.from(JSON.stringify({ r, i, x: Date.now() + 864e5 })).toString('base64url');
  return p + '.' + hmac(p);
};
const auth = role => (q, r, n) => {
  try {
    const t = (q.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const [p, s] = t.split('.');
    if (p && s && safeEq(s, hmac(p))) {
      const o = JSON.parse(Buffer.from(p, 'base64url').toString());
      if (o.r === role && o.x > Date.now()) { q.uid = o.i; return n(); }
    }
  } catch { /* fall through to 401 */ }
  r.status(401).json({ error: 'unauthorized' });
};

/* ---------- Validation helpers ---------- */
const TRADES = ['plumber', 'electrician', 'carpenter', 'painter', 'mason', 'tiler', 'welder', 'mechanic', 'ac_tech', 'gardener'];
/* Allow custom trades from the "More" option */
const isTrade = v => TRADES.includes(v) || (typeof v === 'string' && v.length >= 2 && v.length <= 40);
const clean = v => String(v || '').trim().slice(0, 200);
const okEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

/* Admin login brute-force protection */
const fails = {};
setInterval(() => { const now = Date.now(); for (const k in fails) if (now - fails[k].t > 6e5) delete fails[k]; }, 6e5).unref();

/* Appointment event text: "customer → craftsman" (the admin page splits on this) */
const apTxt = a => `${a.customerName} → ${a.craftsmanName || ''}`;

/* ---------- Health check (open http://<ip>:3000/api/ping from your phone) ---------- */
app.get('/api/ping', (q, r) => r.json({ ok: true, time: new Date().toISOString() }));

/* ---------- Accounts (email + password) ---------- */
const pub = ({ pass, ...u }) => u;
const signup = (col, role, extra) => (q, r) => {
  const e = clean(q.body.email).toLowerCase(), p = String(q.body.password || ''), n = clean(q.body.fullName), d = load();
  if (!okEmail(e) || p.length < 6 || n.length < 2 || (q.body.confirm !== undefined && String(q.body.confirm) !== p)) return r.status(400).json({ error: 'invalid' });
  if (d[col].some(v => v.email === e)) return r.status(409).json({ error: 'exists' });
  const u = { id: id(), email: e, pass: hash(p), fullName: n, createdAt: new Date().toISOString(), ...extra };
  d[col].unshift(u); log(d, role === 'customer' ? 'cus_signup' : 'cra_signup', `${n} · ${e}`); save(d); r.json({ token: sign(role, u.id) });
};
const login = (col, role) => (q, r) => {
  const u = load()[col].find(v => v.email === clean(q.body.email).toLowerCase());
  if (!u || !same(String(q.body.password || ''), u.pass)) return r.status(401).json({ error: 'bad' });
  r.json({ token: sign(role, u.id) });
};

/* ---------- Craftsmen ---------- */
app.post('/api/craftsman/signup', signup('craftsmen', 'craftsman', { status: 'incomplete', rating: 5, available: true }));
app.post('/api/craftsman/login', login('craftsmen', 'craftsman'));
app.get('/api/craftsman/me', auth('craftsman'), (q, r) => {
  const v = load().craftsmen.find(v => v.id === q.uid);
  v ? r.json(pub(v)) : r.status(401).json({ error: 'unauthorized' });
});
app.put('/api/craftsman/me', auth('craftsman'), (q, r) => {
  const d = load(), v = d.craftsmen.find(v => v.id === q.uid);
  if (!v) return r.status(401).json({ error: 'unauthorized' });
  const x = { fullName: clean(q.body.fullName), phone: clean(q.body.phone), city: clean(q.body.city), address: clean(q.body.address), trade: clean(q.body.trade) };
  if (!x.fullName || x.phone.length < 8 || !x.city || !x.address || !isTrade(x.trade)) return r.status(400).json({ error: 'invalid' });
  const first = v.status === 'incomplete'; Object.assign(v, x);
  if (first) { v.status = 'pending'; log(d, 'register', `${x.fullName} (${x.city})`); }
  save(d); r.json(pub(v));
});
app.delete('/api/craftsman/me', auth('craftsman'), (q, r) => {
  const d = load(), v = d.craftsmen.find(v => v.id === q.uid);
  d.craftsmen = d.craftsmen.filter(v => v.id !== q.uid);
  if (v) log(d, 'delete', v.fullName || v.email);
  save(d); r.json({ ok: true });
});
app.get('/api/craftsman/requests', auth('craftsman'), (q, r) => r.json(
  load().appointments.filter(a => a.craftsmanId === q.uid && a.status === 'confirmed')
    .map(({ id, customerName, phone, address, date, note }) => ({ id, customerName, phone, address, date, note }))
));

/* Public list (also for the customer app) */
app.get('/api/public/craftsmen', (q, r) => {
  const city = clean(q.query.city).toLowerCase();
  r.json(load().craftsmen
    .filter(v => v.status === 'accepted' && v.available && (!city || String(v.city || '').toLowerCase().includes(city)))
    .map(({ id, fullName, city, rating, trade }) => ({ id, fullName, city, rating, trade })));
});

/* ---------- Customers ---------- */
app.post('/api/customer/signup', signup('customers', 'customer', {}));
app.post('/api/customer/login', login('customers', 'customer'));
app.get('/api/customer/me', auth('customer'), (q, r) => {
  const c = load().customers.find(c => c.id === q.uid);
  c ? r.json(pub(c)) : r.status(401).json({ error: 'unauthorized' });
});
app.put('/api/customer/me', auth('customer'), (q, r) => {
  const d = load(), c = d.customers.find(c => c.id === q.uid);
  if (!c) return r.status(401).json({ error: 'unauthorized' });
  const x = { fullName: clean(q.body.fullName), phone: clean(q.body.phone), address: clean(q.body.address) };
  if (!x.fullName || x.phone.length < 8) return r.status(400).json({ error: 'invalid' });
  Object.assign(c, x); save(d); r.json(pub(c));
});

const apx = b => ({ customerName: clean(b.customerName), phone: clean(b.phone), address: clean(b.address), date: clean(b.date), note: clean(b.note) });
const apOk = a => a.customerName && a.phone.length >= 8 && a.address && a.date;

app.get('/api/customer/appointments', auth('customer'), (q, r) => {
  const d = load();
  r.json(d.appointments.filter(a => a.customerId === q.uid).map(a => {
    const v = d.craftsmen.find(v => v.id === a.craftsmanId);
    return a.status === 'confirmed' && v ? { ...a, craftsmanPhone: v.phone } : a;
  }));
});
app.post('/api/customer/appointments', auth('customer'), (q, r) => {
  const d = load(), drv = d.craftsmen.find(v => v.id === q.body.craftsmanId && v.status === 'accepted'), x = apx(q.body);
  if (!drv || !apOk(x)) return r.status(400).json({ error: 'invalid' });
  const a = { id: id(), customerId: q.uid, craftsmanId: drv.id, craftsmanName: drv.fullName, ...x, status: 'pending', createdAt: new Date().toISOString() };
  d.appointments.unshift(a); log(d, 'booking', apTxt(a)); save(d); r.json(a);
});
app.put('/api/customer/appointments/:id', auth('customer'), (q, r) => {
  const d = load(), a = d.appointments.find(a => a.id === q.params.id && a.customerId === q.uid), x = apx(q.body);
  if (!a) return r.status(404).json({ error: 'nf' });
  if (!apOk(x)) return r.status(400).json({ error: 'invalid' });
  Object.assign(a, x, { status: 'pending' }); log(d, 'appt_edited', apTxt(a)); save(d); r.json(a);
});
app.delete('/api/customer/appointments/:id', auth('customer'), (q, r) => {
  const d = load(), a = d.appointments.find(a => a.id === q.params.id && a.customerId === q.uid);
  d.appointments = d.appointments.filter(a => !(a.id === q.params.id && a.customerId === q.uid));
  if (a) log(d, 'appt_cancelled', apTxt(a));
  save(d); r.json({ ok: true });
});

/* ---------- Admin ---------- */
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) console.warn('⚠  ADMIN_EMAIL / ADMIN_PASSWORD are not set in .env — admin login is disabled.');

app.post('/api/admin/login', (q, r) => {
  const ip = q.ip, f = fails[ip] || { n: 0, t: 0 };
  if (f.n >= 5 && Date.now() - f.t < 6e5) return r.status(429).json({ error: 'locked' });
  /* Login is refused when the admin credentials are not configured (prevents empty == empty bypass) */
  const ok = !!ADMIN_EMAIL && !!ADMIN_PASSWORD
    && safeEq(clean(q.body.email).toLowerCase(), ADMIN_EMAIL)
    && safeEq(String(q.body.password || ''), ADMIN_PASSWORD);
  if (!ok) { fails[ip] = { n: f.n + 1, t: Date.now() }; return r.status(401).json({ error: 'bad' }); }
  delete fails[ip]; r.json({ token: sign('admin', 'a') });
});
app.get('/api/admin/stats', auth('admin'), (q, r) => {
  const d = load(), ds = d.craftsmen.filter(v => v.status !== 'incomplete');
  const by = (arr, k) => arr.reduce((m, v) => (m[v[k]] = (m[v[k]] || 0) + 1, m), {});
  const week = Date.now() - 7 * 864e5;
  r.json({
    total: ds.length, status: by(ds, 'status'), cities: by(ds, 'city'),
    appointments: d.appointments.length, pendingAppts: d.appointments.filter(a => a.status === 'pending').length,
    newWeek: ds.filter(v => +new Date(v.createdAt) > week).length, events: d.events.slice(0, 40)
  });
});
app.get('/api/admin/craftsmen', auth('admin'), (q, r) => {
  const d = load();
  r.json(d.craftsmen.filter(v => v.status !== 'incomplete').map(v => ({
    ...pub(v),
    jobs: d.appointments.filter(a => a.craftsmanId === v.id && a.status === 'confirmed').length,
    requests: d.appointments.filter(a => a.craftsmanId === v.id).length
  })));
});
app.put('/api/admin/craftsmen/:id', auth('admin'), (q, r) => {
  const d = load(), v = d.craftsmen.find(v => v.id === q.params.id);
  if (!v) return r.status(404).json({ error: 'nf' });
  ['fullName', 'phone', 'city', 'address'].forEach(k => q.body[k] !== undefined && (v[k] = clean(q.body[k])));
  if (['pending', 'accepted', 'rejected'].includes(q.body.status)) { v.status = q.body.status; log(d, v.status, v.fullName); }
  if (typeof q.body.available === 'boolean') v.available = q.body.available;
  save(d); r.json(pub(v));
});
app.delete('/api/admin/craftsmen/:id', auth('admin'), (q, r) => {
  const d = load(), v = d.craftsmen.find(v => v.id === q.params.id);
  d.craftsmen = d.craftsmen.filter(v => v.id !== q.params.id);
  if (v) log(d, 'delete', v.fullName);
  save(d); r.json({ ok: true });
});
app.get('/api/admin/customers', auth('admin'), (q, r) => {
  const d = load();
  r.json(d.customers.map(c => {
    const a = d.appointments.filter(a => a.customerId === c.id);
    return {
      id: c.id, email: c.email, name: c.fullName || (a[0] ? a[0].customerName : ''), phone: c.phone || (a[0] ? a[0].phone : ''),
      requests: a.length, confirmed: a.filter(x => x.status === 'confirmed').length, last: a[0] ? a[0].createdAt : null
    };
  }));
});
app.get('/api/admin/appointments', auth('admin'), (q, r) => r.json(load().appointments));
app.put('/api/admin/appointments/:id', auth('admin'), (q, r) => {
  const d = load(), a = d.appointments.find(a => a.id === q.params.id);
  if (!a) return r.status(404).json({ error: 'nf' });
  if (['pending', 'confirmed', 'rejected'].includes(q.body.status)) { a.status = q.body.status; log(d, 'appt_' + a.status, apTxt(a)); }
  save(d); r.json(a);
});
app.delete('/api/admin/appointments/:id', auth('admin'), (q, r) => {
  const d = load(), a = d.appointments.find(a => a.id === q.params.id);
  d.appointments = d.appointments.filter(a => a.id !== q.params.id);
  if (a) log(d, 'appt_deleted', apTxt(a));
  save(d); r.json({ ok: true });
});
app.get('/api/admin/export', auth('admin'), (q, r) => {
  /* Quote every cell and neutralise spreadsheet formulas (= + - @) */
  const e = s => { s = String(s == null ? '' : s); if (/^[=+\-@]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const rows = load().craftsmen.map(v => [v.fullName, v.email, v.phone, v.city, v.address, v.status, v.createdAt].map(e).join(','));
  r.type('text/csv').send('\ufefffullName,email,phone,city,address,status,createdAt\n' + rows.join('\n'));
});

/* ---------- Fallbacks ---------- */
app.use('/api', (q, r) => r.status(404).json({ error: 'nf' }));
app.use((err, q, r, n) => {
  if (err && err.type === 'entity.parse.failed') return r.status(400).json({ error: 'invalid' });
  if (err && err.type === 'entity.too.large') return r.status(413).json({ error: 'too_large' });
  console.error(err);
  r.status(500).json({ error: 'server' });
});

/* ---------- Server ---------- */
const P = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0'; /* listen on all network interfaces so phones on the same Wi-Fi can connect */

/* Real LAN addresses of this machine (no hard-coded IP) */
const lanIPs = () => Object.values(os.networkInterfaces()).flat()
  .filter(i => i && (i.family === 'IPv4' || i.family === 4) && !i.internal)
  .map(i => i.address);

const server = app.listen(P, HOST, () => {
  console.log(`Hirafi running → http://localhost:${P}`);
  lanIPs().forEach(ip => console.log(`Hirafi running → http://${ip}:${P}   (same Wi-Fi devices)`));
  console.log('If the LAN address does not open: allow TCP port ' + P + ' in Windows Firewall (see README / chat).');
});
server.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error(`✖ Port ${P} is already in use. Close the other server or set PORT in .env.`);
  else console.error('✖ Server error:', e.message);
  process.exit(1);
});
