// سرور بی‌سیم محلی — بدون نیاز به هیچ کتابخانه‌ی خارجی (فقط Node.js)
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const PORT = process.env.PORT || 8443;
const HOSTED = !!process.env.PORT; // روی هاست آنلاین، خود هاست HTTPS می‌دهد
const MAX_PER_ROOM = 12;
const MAX_MSG = 1024 * 1024;

// ---------- WebSocket ساده (RFC 6455) ----------
class Conn extends EventEmitter {
  constructor(socket) {
    super();
    this.socket = socket;
    this.readyState = 1;
    this.buf = Buffer.alloc(0);
    this.frag = null;
    socket.on('data', (d) => this._data(d));
    socket.on('close', () => this._closed());
    socket.on('error', () => this._closed());
  }
  _closed() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.emit('close');
  }
  _data(d) {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      const b = this.buf;
      if (b.length < 2) return;
      const fin = (b[0] & 0x80) !== 0;
      const op = b[0] & 0x0f;
      const masked = (b[1] & 0x80) !== 0;
      let len = b[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
      if (len > MAX_MSG) { this.socket.destroy(); return; }
      const need = off + (masked ? 4 : 0) + len;
      if (b.length < need) return;
      let payload = b.subarray(off + (masked ? 4 : 0), need);
      if (masked) {
        const mask = b.subarray(off, off + 4);
        const out = Buffer.alloc(len);
        for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
        payload = out;
      }
      this.buf = b.subarray(need);
      this._frame(fin, op, payload);
    }
  }
  _frame(fin, op, payload) {
    if (op === 8) { this.close(); return; }
    if (op === 9) { this._write(0xA, payload); return; }
    if (op === 10) return;
    if (op === 1 || op === 2) this.frag = { op, parts: [payload] };
    else if (op === 0 && this.frag) this.frag.parts.push(payload);
    else return;
    if (fin) {
      const full = Buffer.concat(this.frag.parts);
      const isText = this.frag.op === 1;
      this.frag = null;
      if (isText) this.emit('message', full.toString('utf8'));
    }
  }
  _write(op, payload) {
    if (this.readyState !== 1 || this.socket.destroyed) return;
    const len = payload.length;
    let head;
    if (len < 126) head = Buffer.from([0x80 | op, len]);
    else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
    else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
    this.socket.write(Buffer.concat([head, payload]));
  }
  send(str) { this._write(1, Buffer.from(str, 'utf8')); }
  ping() { this._write(9, Buffer.alloc(0)); }
  close() {
    if (this.readyState !== 1) return;
    this._write(8, Buffer.alloc(0));
    this.readyState = 2;
    this.socket.end();
  }
}

function handleUpgrade(req, socket, onConn) {
  const key = req.headers['sec-websocket-key'];
  if (!key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  onConn(new Conn(socket));
}

// ---------- سرور ----------
function localIPs() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces()))
    for (const i of list || []) if (i.family === 'IPv4' && !i.internal) out.push(i.address);
  return out;
}

let opts = null;
if (!HOSTED) {
  try {
    opts = { key: fs.readFileSync(path.join(__dirname, 'key.pem')), cert: fs.readFileSync(path.join(__dirname, 'cert.pem')) };
  } catch (e) {
    console.error('فایل key.pem و cert.pem کنار server.js پیدا نشد. پوشه را کامل از ZIP خارج کنید.');
    process.exit(1);
  }
}

const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));

// تنظیمات اینترنتی (اختیاری):
//   ACCESS_CODE          رمز ورود به بی‌سیم
//   TURN_CREDENTIALS_URL آدرس دریافت اطلاعات TURN (مثلاً از Metered)
//   TURN_URL/TURN_USER/TURN_PASS  یا تنظیم دستی TURN
//   ICE_JSON             آرایه‌ی کامل iceServers به صورت JSON
const ACCESS_CODE = process.env.ACCESS_CODE || '';
let iceCache = { t: 0, v: null };
async function getIce() {
  const base = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.ICE_JSON) { try { return JSON.parse(process.env.ICE_JSON); } catch {} }
  if (process.env.TURN_CREDENTIALS_URL) {
    if (iceCache.v && Date.now() - iceCache.t < 3600e3) return iceCache.v;
    try {
      const r = await fetch(process.env.TURN_CREDENTIALS_URL);
      const arr = await r.json();
      if (Array.isArray(arr) && arr.length) { iceCache = { t: Date.now(), v: arr }; return arr; }
    } catch (e) { console.error('دریافت اطلاعات TURN ناموفق بود:', e.message); }
  }
  if (process.env.TURN_URL) {
    return [...base, { urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER || '', credential: process.env.TURN_PASS || '' }];
  }
  return base;
}

const handler = async (req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/ice') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(await getIce()));
  } else if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
  }
};
const server = opts ? https.createServer(opts, handler) : http.createServer(handler);

const rooms = new Map();
let nextId = 1;
const send = (ws, obj) => { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); };

function onConnection(ws) {
  ws.id = String(nextId++);
  ws.alive = true;

  ws.on('message', (raw) => {
    ws.alive = true;
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.type === 'join') {
      if (ACCESS_CODE && String(m.code || '') !== ACCESS_CODE) { send(ws, { type: 'denied' }); setTimeout(() => ws.close(), 100); return; }
      ws.name = String(m.name || 'گوشی').slice(0, 30);
      ws.room = String(m.room || 'main').slice(0, 30);
      if (!rooms.has(ws.room)) rooms.set(ws.room, new Set());
      const room = rooms.get(ws.room);
      if (room.size >= MAX_PER_ROOM) return send(ws, { type: 'full' });
      send(ws, { type: 'welcome', id: ws.id, peers: [...room].map(p => ({ id: p.id, name: p.name })) });
      room.forEach(p => send(p, { type: 'peer-joined', id: ws.id, name: ws.name }));
      room.add(ws);
      return;
    }

    const room = rooms.get(ws.room);
    if (!room) return;

    if (['offer', 'answer', 'ice'].includes(m.type)) {
      for (const p of room) if (p.id === m.to) send(p, { type: m.type, from: ws.id, data: m.data });
    } else if (m.type === 'talking') {
      for (const p of room) if (p !== ws) send(p, { type: 'talking', id: ws.id, on: !!m.on });
    } else if (m.type === 'crackle') {
      for (const p of room) if (p !== ws) send(p, { type: 'crackle', id: ws.id });
    }
  });

  ws.on('close', () => {
    const room = rooms.get(ws.room);
    if (!room) return;
    room.delete(ws);
    room.forEach(p => send(p, { type: 'peer-left', id: ws.id }));
    if (room.size === 0) rooms.delete(ws.room);
  });
}

server.on('upgrade', (req, socket) => handleUpgrade(req, socket, onConnection));

// نگه داشتن اتصال‌ها زنده
setInterval(() => {
  for (const room of rooms.values()) for (const ws of room) ws.ping();
}, 25000);

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error('پورت ' + PORT + ' در حال استفاده است. پنجره‌های قبلی سرور را ببندید.');
  else console.error(e);
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  const scheme = opts ? 'https' : 'http';
  console.log('\nبی‌سیم آماده است. این آدرس را در مرورگر همه‌ی گوشی‌ها باز کنید:\n');
  if (HOSTED) console.log('   (روی هاست آنلاین اجرا شد)');
  else localIPs().forEach(ip => console.log(`   ${scheme}://${ip}:${PORT}`));
  console.log('');
});
