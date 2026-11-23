// 자기소개 페이지 + WebAuthn(패스키) 인증. 비밀번호는 어디에도 없음.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const CHALLENGE_TTL_MS = 2 * 60 * 1000;   // 챌린지 유효 2분
const SESSION_TTL_MS = 60 * 60 * 1000;    // 세션 1시간
const PUBLIC_DIR = path.join(__dirname, 'public');
const RP_NAME = '내 소개 페이지';

// ---------- 저장소 (공개키 메타데이터만 저장) ----------
let db = { users: {} };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch {}
const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
// users[name] = { id, name, passkeys:[{id, publicKey, counter, transports, name, createdAt, deviceType, backedUp}], notes:[...] }

const challenges = new Map(); // challenge -> { type, user, exp }   (사용하면 즉시 삭제 = 1회용)
const sessions = new Map();   // sid -> { user, exp }               (서버에만 보관)
const usedLog = [];           // 증거용: 소진된 챌린지 기록

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const newChallengeStore = (type, user) => (ch) => challenges.set(ch, { type, user, exp: Date.now() + CHALLENGE_TTL_MS });
function takeChallenge(ch, type) {
  const c = challenges.get(ch);
  challenges.delete(ch); // 성공/실패 상관없이 소진
  if (!c) return { error: '이미 사용했거나 발급한 적 없는 챌린지입니다' };
  if (c.type !== type) return { error: '챌린지 용도가 다릅니다' };
  if (c.exp < Date.now()) return { error: '챌린지 유효시간(2분)이 지났습니다' };
  return { c };
}
setInterval(() => {
  const t = Date.now();
  for (const [k, v] of challenges) if (v.exp < t) challenges.delete(k);
  for (const [k, v] of sessions) if (v.exp < t) sessions.delete(k);
}, 30000).unref();

// ---------- 유틸 ----------
function send(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', (d) => { s += d; if (s.length > 100_000) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(s ? JSON.parse(s) : {}); } catch (e) { reject(e); } });
  });
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); });
  return o;
}
function rpInfo(req) {
  const host = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0].trim();
  const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
  return {
    rpID: process.env.RP_ID || host.split(':')[0],
    origin: process.env.ORIGIN || `${proto}://${host}`,
    secure: proto === 'https',
  };
}
function currentUser(req) {
  const sid = cookies(req).sid;
  const s = sid && sessions.get(sid);
  if (!s || s.exp < Date.now() || !db.users[s.user]) return null;
  return db.users[s.user];
}
function startSession(res, req, username) {
  const sid = crypto.randomBytes(32).toString('base64url');
  sessions.set(sid, { user: username, exp: Date.now() + SESSION_TTL_MS });
  const { secure } = rpInfo(req);
  return `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secure ? '; Secure' : ''}`;
}
const publicKeyView = (p) => ({
  id: p.id, name: p.name, createdAt: p.createdAt, deviceType: p.deviceType, backedUp: p.backedUp,
  transports: p.transports || [], storedAt: storageHint(p),
});
function storageHint(p) {
  if (p.deviceType === 'multiDevice' && p.backedUp) return '동기화되는 패스키(구글 비밀번호 관리자·iCloud 키체인 등)';
  if (p.deviceType === 'singleDevice') return '이 기기/보안 키 안에만 저장(동기화 안 됨)';
  return '동기화 가능 패스키';
}
const SEED = (u) => [
  `[가상] ${u}의 준비 중인 프로젝트 메모: 할 일 앱 프로토타입`,
  `[가상] ${u}의 지원하려는 곳 목록: 가짜회사 A, 가짜회사 B`,
  `[가상] ${u}의 개인 회고: 이번 달에는 꾸준히 운동하기`,
];
const NAME_RE = /^[a-zA-Z0-9가-힣_.-]{2,20}$/;

// ---------- API ----------
async function api(req, res, url) {
  const r = rpInfo(req);
  let body = {};
  if (req.method === 'POST' || req.method === 'DELETE') {
    try { body = await readBody(req); } catch { return send(res, 400, { error: '요청 본문이 올바르지 않습니다' }); }
  }
  const p = url.pathname;

  // --- 등록 ① 옵션(챌린지 발급). 새 계정 생성 또는 로그인 상태에서 패스키 추가
  if (p === '/api/register/options' && req.method === 'POST') {
    let user = currentUser(req);
    let userName;
    if (user) {
      userName = user.name;                // 로그인 상태: 본문의 username은 무시(타 계정 지정 불가)
    } else {
      userName = String(body.username || '').trim();
      if (!NAME_RE.test(userName)) return send(res, 400, { error: '계정 이름은 2~20자(한글/영문/숫자/_.-)로 입력하세요' });
      if (db.users[userName]) return send(res, 409, { error: '이미 있는 계정입니다. 기존 계정에 패스키를 추가하려면 먼저 로그인하세요' });
    }
    const existing = user ? user.passkeys : [];
    const userId = user ? unb64(user.id) : crypto.randomBytes(32);
    const opts = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: r.rpID, userName, userID: userId,
      attestationType: 'none',
      excludeCredentials: existing.map((k) => ({ id: k.id, transports: k.transports })), // 같은 인증기 중복 등록 방지
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });
    challenges.set(opts.challenge, { type: 'reg', user: userName, userId: b64(userId), exp: Date.now() + CHALLENGE_TTL_MS, isNew: !user });
    return send(res, 200, opts);
  }

  // --- 등록 ② 검증 + 공개키 저장
  if (p === '/api/register/verify' && req.method === 'POST') {
    const resp = body.response;
    let ch;
    try { ch = JSON.parse(Buffer.from(resp.response.clientDataJSON, 'base64url').toString()).challenge; } catch { return send(res, 400, { error: '등록 응답 형식 오류' }); }
    const t = takeChallenge(ch, 'reg');
    if (t.error) return send(res, 400, { error: t.error });
    const c = t.c;
    const logged = currentUser(req);
    if (logged ? logged.name !== c.user : false) return send(res, 403, { error: '챌린지를 발급받은 계정과 다릅니다' });
    if (!logged && !c.isNew) return send(res, 403, { error: '로그인이 필요합니다' });
    let v;
    try {
      v = await verifyRegistrationResponse({ response: resp, expectedChallenge: ch, expectedOrigin: r.origin, expectedRPID: r.rpID });
    } catch (e) { return send(res, 400, { error: '등록 검증 실패: ' + e.message }); }
    if (!v.verified) return send(res, 400, { error: '등록 검증 실패' });
    const info = v.registrationInfo;
    let user = db.users[c.user];
    if (!user) {
      if (!c.isNew) return send(res, 400, { error: '계정 없음' });
      user = db.users[c.user] = { id: c.userId, name: c.user, passkeys: [], notes: SEED(c.user) };
    }
    if (user.passkeys.some((k) => k.id === info.credential.id)) return send(res, 409, { error: '이미 등록된 패스키입니다' });
    const pk = {
      id: info.credential.id,
      publicKey: b64(info.credential.publicKey),       // 공개키만 저장
      counter: info.credential.counter,
      transports: info.credential.transports || resp.response.transports || [],
      name: String(body.name || '').trim().slice(0, 30) || `패스키 ${user.passkeys.length + 1}`,
      createdAt: new Date().toISOString(),
      deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp,
    };
    user.passkeys.push(pk); save();
    const headers = {};
    if (!logged) headers['Set-Cookie'] = startSession(res, req, user.name);
    return send(res, 200, {
      verified: true, user: user.name,
      stored: { id: pk.id, publicKey: pk.publicKey, counter: pk.counter, deviceType: pk.deviceType, backedUp: pk.backedUp },
      note: '서버에는 공개키와 자격 증명 ID 같은 공개 메타데이터만 저장됩니다. 개인키·비밀번호는 서버로 전송되지 않습니다.',
    }, headers);
  }

  // --- 로그인 ① 새 챌린지
  if (p === '/api/login/options' && req.method === 'POST') {
    const name = String(body.username || '').trim();
    const u = name && db.users[name];
    const opts = await generateAuthenticationOptions({
      rpID: r.rpID, userVerification: 'preferred',
      allowCredentials: u ? u.passkeys.map((k) => ({ id: k.id, transports: k.transports })) : undefined,
    });
    challenges.set(opts.challenge, { type: 'auth', exp: Date.now() + CHALLENGE_TTL_MS });
    return send(res, 200, opts);
  }

  // --- 로그인 ② 서명 검증 (저장된 공개키로)
  if (p === '/api/login/verify' && req.method === 'POST') {
    const resp = body.response;
    let ch;
    try { ch = JSON.parse(Buffer.from(resp.response.clientDataJSON, 'base64url').toString()).challenge; } catch { return send(res, 400, { error: '로그인 응답 형식 오류' }); }
    const t = takeChallenge(ch, 'auth');
    if (t.error) { usedLog.push({ at: Date.now(), challenge: ch.slice(0, 8) + '…', reason: t.error }); return send(res, 400, { error: t.error }); }
    let owner, key;
    for (const u of Object.values(db.users)) { const k = u.passkeys.find((x) => x.id === resp.id); if (k) { owner = u; key = k; } }
    if (!key) return send(res, 401, { error: '등록되지 않았거나 삭제된 패스키입니다' });
    let v;
    try {
      v = await verifyAuthenticationResponse({
        response: resp, expectedChallenge: ch, expectedOrigin: r.origin, expectedRPID: r.rpID,
        credential: { id: key.id, publicKey: unb64(key.publicKey), counter: key.counter, transports: key.transports },
      });
    } catch (e) { return send(res, 401, { error: '서명 검증 실패: ' + e.message }); }
    if (!v.verified) return send(res, 401, { error: '서명 검증 실패' });
    key.counter = v.authenticationInfo.newCounter; save();
    return send(res, 200, { verified: true, user: owner.name }, { 'Set-Cookie': startSession(res, req, owner.name) });
  }

  if (p === '/api/logout' && req.method === 'POST') {
    const sid = cookies(req).sid; if (sid) sessions.delete(sid);
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0' });
  }

  // --- 이하 인증 필요 (비공개 영역)
  const me = currentUser(req);
  if (!me) return send(res, 401, { error: '로그인이 필요합니다' });

  if (p === '/api/private' && req.method === 'GET')   // 비공개 자료: 항상 "세션의 계정" 것만. 본문/쿼리의 계정 지정은 무시
    return send(res, 200, { user: me.name, notes: me.notes });
  if (p === '/api/private/notes' && req.method === 'POST') {
    const text = String(body.text || '').trim().slice(0, 200);
    if (!text) return send(res, 400, { error: '내용을 입력하세요' });
    me.notes.push(text); save(); return send(res, 200, { notes: me.notes });
  }
  if (p === '/api/passkeys' && req.method === 'GET')
    return send(res, 200, { user: me.name, passkeys: me.passkeys.map(publicKeyView) });
  if (p.startsWith('/api/passkeys/') && req.method === 'DELETE') {
    const id = decodeURIComponent(p.slice('/api/passkeys/'.length));
    const i = me.passkeys.findIndex((k) => k.id === id);
    if (i < 0) return send(res, 404, { error: '내 계정의 패스키가 아닙니다' }); // 타 계정 것은 존재 여부도 숨김
    if (me.passkeys.length === 1) return send(res, 409, { error: '마지막 패스키는 삭제할 수 없습니다(삭제하면 로그인 불가). 먼저 다른 패스키를 등록하세요' });
    me.passkeys.splice(i, 1); save();
    return send(res, 200, { deleted: id, remaining: me.passkeys.length });
  }
  return send(res, 404, { error: 'not found' });
}

// ---------- 정적 파일 ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
function serveStatic(req, res, url) {
  // 비공개 화면(private.html)은 로그인 없이는 아예 내려주지 않음
  let f = url.pathname === '/' ? '/index.html' : url.pathname;
  if (f === '/private.html' && !currentUser(req)) { res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('401 로그인이 필요합니다'); }
  const full = path.normalize(path.join(PUBLIC_DIR, f));
  if (!full.startsWith(PUBLIC_DIR) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(full).pipe(res);
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  (url.pathname.startsWith('/api/') ? api(req, res, url).catch((e) => { console.error(e); send(res, 500, { error: 'server error' }); }) : serveStatic(req, res, url));
}).listen(PORT, () => console.log('listening on', PORT));
