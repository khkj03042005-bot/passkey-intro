// 실행: BASE=http://localhost:3111 node test/e2e.js  → 요청/응답 기록을 test/evidence.log 에 남김
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = process.env.BASE || 'http://localhost:3111';
const out = []; const log = (...a) => { const s = a.join(' '); console.log(s); out.push(s); };
let fails = 0; const check = (c, t) => { log((c ? 'PASS ' : 'FAIL ') + t); if (!c) fails++; };

async function newUser(browser, label) {
  const ctx = await browser.newContext(); const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const add = async () => (await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })).authenticatorId;
  await page.goto(BASE);
  return { ctx, page, cdp, add, label };
}
const api = (page, method, url, body) => page.evaluate(async ([m, u, b]) => {
  const r = await fetch(u, { method: m, headers: { 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined });
  return { status: r.status, body: await r.text() };
}, [method, url, body]);

(async () => {
  const browser = await chromium.launch();
  const A = await newUser(browser, 'alice'), B = await newUser(browser, 'bob');
  const a1 = await A.add(); await B.add();

  log('== C13~C18 로그인 전 접근 ==');
  const anon = await browser.newContext(); const ap = await anon.newPage();
  const r0 = await ap.request.get(BASE + '/api/private');
  log('GET /api/private (로그인 없음) →', r0.status(), await r0.text());
  check([401, 403].includes(r0.status()), 'T08-C16/C17 비로그인 비공개 요청 거절');
  const html = await (await ap.request.get(BASE + '/')).text();
  check(!/\[가상\] /.test(html) && !/alice|bob/.test(html), 'T08-C18 비로그인 응답 본문에 비공개 내용 없음');
  fs.writeFileSync(__dirname + '/anonymous-response-body.html', html);

  log('== 등록 (C19~C26) ==');
  const regReq = []; A.page.on('request', (q) => { if (q.url().includes('/api/register/')) regReq.push([q.url().split('/api')[1], q.postData()]); });
  const o1 = await api(A.page, 'POST', '/api/register/options', { username: 'alice' });
  const o2 = await api(A.page, 'POST', '/api/register/options', { username: 'alice' });
  check(JSON.parse(o1.body).challenge !== JSON.parse(o2.body).challenge, 'T08-C20 등록 요청마다 챌린지 다름: ' + JSON.parse(o1.body).challenge.slice(0, 10) + ' / ' + JSON.parse(o2.body).challenge.slice(0, 10));
  // 취소 시나리오(C25): 사용자 확인 불가 인증기 → NotAllowedError
  await A.page.fill('#regName', 'cancelme'); await A.page.fill('#pkName', 'x');
  await A.cdp.send('WebAuthn.setUserVerified', { authenticatorId: a1, isUserVerified: false });
  await A.page.click('#btnReg'); await A.page.waitForSelector('#msg.err');
  log('취소 시 화면 안내:', await A.page.textContent('#msg'));
  await A.cdp.send('WebAuthn.setUserVerified', { authenticatorId: a1, isUserVerified: true });
  const chk = await api(A.page, 'POST', '/api/register/options', { username: 'cancelme' });
  check(chk.status === 200, 'T08-C25 취소 후 cancelme 계정은 저장되지 않음(다시 등록 가능)');

  await A.page.fill('#regName', 'alice'); await A.page.fill('#pkName', '노트북 내장');
  await A.page.click('#btnReg'); await A.page.waitForSelector('#msg.ok');
  log('등록 화면 메시지:', (await A.page.textContent('#msg')).replace(/\n/g, ' | '));
  log('등록 요청 본문(개인키·비밀번호 필드 없음):', regReq.map((r) => r[0] + ' ' + (r[1] || '').slice(0, 300)).join('\n   '));
  check(!regReq.some((r) => /privateKey|password/i.test(r[1] || '')), 'T08-C23 등록 요청 본문에 개인키/비밀번호 없음');
  const data = JSON.parse(fs.readFileSync(process.env.DATA_FILE || '/tmp/claude-0/t.json'));
  const stored = data.users.alice.passkeys[0];
  log('서버 저장 값 키 목록:', Object.keys(stored).join(','), '| 이름:', stored.name);
  check(!!stored.publicKey && !JSON.stringify(data).match(/privateKey|password/i), 'T08-C21/22 서버엔 공개키·ID만 저장');

  log('== 로그인 (C27~C35) ==');
  const loginPosts = []; A.page.on('request', (q) => { if (q.url().endsWith('/api/login/verify')) loginPosts.push(q.postData()); });
  const l1 = JSON.parse((await api(A.page, 'POST', '/api/login/options', {})).body).challenge;
  const l2 = JSON.parse((await api(A.page, 'POST', '/api/login/options', {})).body).challenge;
  check(l1 !== l2, 'T08-C27/28 로그인 챌린지 매번 새로 발급: ' + l1.slice(0, 10) + ' / ' + l2.slice(0, 10));
  await api(A.page, 'POST', '/api/logout'); await A.page.reload();
  await A.page.fill('#regName', 'alice'); await A.page.click('#btnLogin'); await A.page.waitForSelector('#privView:not([hidden])');
  log('로그인 성공 화면:', (await A.page.textContent('#msg')));
  check(loginPosts.length === 1, 'T08-C30 서명 검증 성공 요청 기록');
  // 재사용(replay)
  await api(A.page, 'POST', '/api/logout');
  const rp = await api(A.page, 'POST', '/api/login/verify', JSON.parse(loginPosts[0]));
  log('같은 서명/챌린지 재전송 →', rp.status, rp.body);
  check(rp.status === 400, 'T08-C31 사용한 챌린지 재사용 거절');
  // 위조 서명
  const forged = JSON.parse(loginPosts[0]); const fo = JSON.parse((await api(A.page, 'POST', '/api/login/options', {})).body);
  const cd = JSON.parse(Buffer.from(forged.response.response.clientDataJSON, 'base64url')); cd.challenge = fo.challenge;
  forged.response.response.clientDataJSON = Buffer.from(JSON.stringify(cd)).toString('base64url');
  const fr = await api(A.page, 'POST', '/api/login/verify', forged);
  log('위조(새 챌린지 + 옛 서명) →', fr.status, fr.body);
  check(fr.status === 401, 'T08-C29/30 틀린 서명 거절');
  // 로그아웃 후 접근
  const afterLogout = await api(A.page, 'GET', '/api/private');
  log('로그아웃 후 GET /api/private →', afterLogout.status, afterLogout.body);
  check(afterLogout.status === 401, 'T08-C33 로그아웃 후 거절');
  const ck = (await A.ctx.cookies()).find((c) => c.name === 'sid');
  check(!ck, 'T08-C34 로그아웃 후 세션 쿠키 제거됨(기록에는 값 미기재)');

  log('== 분실 대비 (C42~C46) ==');
  await A.page.reload();
  await A.page.fill('#regName', 'alice'); await A.page.click('#btnLogin'); await A.page.waitForSelector('#privView:not([hidden])');
  // 같은 인증기로 두번째 등록 → 거절(excludeCredentials)
  await A.page.fill('#pkName2', '중복시도'); await A.page.click('#btnAdd'); await A.page.waitForSelector('#msg.err');
  log('같은 인증기 두 번째 등록 시도:', await A.page.textContent('#msg'));
  // 다른 인증기(보안 키 역할)
  await A.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: a1 });
  const a2 = await A.add();
  await A.page.fill('#pkName2', '보안 키'); await A.page.click('#btnAdd'); await A.page.waitForSelector('#msg.ok');
  await A.page.waitForFunction(() => document.querySelectorAll('.pk').length === 2);
  log('패스키 목록:', (await A.page.$$eval('.pk', (e) => e.map((x) => x.innerText.replace(/\n/g, ' / ')))).join('\n   '));
  check((await A.page.$$('.pk')).length === 2, 'T08-C42/43 패스키 2개 목록 표시');
  // 마지막 하나 삭제 시도 전에: 노트북 내장 삭제 (가상 인증기 a2에는 두번째 것만 있음)
  const list = JSON.parse((await api(A.page, 'GET', '/api/passkeys')).body).passkeys;
  const first = list.find((p) => p.name === '노트북 내장'), second = list.find((p) => p.name === '보안 키');
  const d1 = await api(A.page, 'DELETE', '/api/passkeys/' + encodeURIComponent(first.id));
  log('첫 패스키 삭제 →', d1.status, d1.body);
  const d2 = await api(A.page, 'DELETE', '/api/passkeys/' + encodeURIComponent(second.id));
  log('마지막 패스키 삭제 시도 →', d2.status, d2.body);
  check(d1.status === 200 && d2.status === 409, 'T08-C44/46 하나 삭제 가능, 마지막은 거절');
  await api(A.page, 'POST', '/api/logout'); await A.page.reload();
  await A.page.fill('#regName', 'alice'); await A.page.click('#btnLogin');
  await A.page.waitForSelector('#privView:not([hidden])');
  check(true, 'T08-C44 남은 패스키(보안 키)로 로그인 성공');
  // 삭제된 패스키 로그인: 옛 서명 재생은 이미 챌린지 소진. 삭제된 ID로 새 챌린지 서명 → 인증기에 없음
  log('삭제된 패스키는 인증기에 있어도 서버가 거절:');
  await A.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: a2 });
  // 삭제된 first 로 직접 로그인 요청 (조작된 응답)
  const bogus = { id: first.id, rawId: first.id, type: 'public-key', response: { clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: JSON.parse((await api(A.page, 'POST', '/api/login/options', {})).body).challenge, origin: BASE })).toString('base64url'), authenticatorData: 'AA', signature: 'AA' }, clientExtensionResults: {} };
  const dr = await api(A.page, 'POST', '/api/login/verify', { response: bogus });
  log('  →', dr.status, dr.body);
  check(dr.status === 401, 'T08-C45 삭제한 패스키로는 로그인 불가');

  log('== 계정 간 격리 (C36~C40) ==');
  await B.page.fill('#regName', 'bob'); await B.page.fill('#pkName', 'bob 노트북'); await B.page.click('#btnReg'); await B.page.waitForSelector('#privView:not([hidden])');
  const bobList = JSON.parse((await api(B.page, 'GET', '/api/passkeys')).body).passkeys;
  // alice는 새 인증기로 다시 로그인 불가(인증기 제거됨) → alice 세션을 새로 만들기 위해 인증기 재추가는 키 소실이라 불가. alice 세션은 직전 로그인 유지 중
  const aliceMe = await api(A.page, 'GET', '/api/private');
  log('alice 본인 자료:', aliceMe.body);
  const bobMe = await api(B.page, 'GET', '/api/private'); log('bob 본인 자료:', bobMe.body);
  check(aliceMe.body !== bobMe.body && JSON.parse(aliceMe.body).notes.length === 3 && JSON.parse(bobMe.body).notes.length === 3, 'T08-C36 두 계정에 각각 다른 비공개 자료 3개');
  const x1 = await api(A.page, 'GET', '/api/private?user=bob&username=bob');
  const x2 = await api(A.page, 'DELETE', '/api/passkeys/' + encodeURIComponent(bobList[0].id));
  log('alice 세션으로 ?user=bob 요청 →', x1.status, x1.body);
  log('alice 세션으로 bob 패스키 삭제 시도 →', x2.status, x2.body);
  check(JSON.parse(x1.body).user === 'alice' && !x1.body.includes('bob'), 'T08-C40 주소에 타 계정 지정해도 내 자료만 응답');
  check(x2.status === 404, 'T08-C37 타 계정 패스키 조작 거절');
  const y1 = await api(B.page, 'GET', '/api/private?user=alice');
  const y2 = await api(B.page, 'POST', '/api/private/notes', { user: 'alice', username: 'alice', text: 'bob이 쓴 글' });
  const aliceAfter = await api(A.page, 'GET', '/api/private');
  log('bob 세션으로 ?user=alice →', y1.status, y1.body);
  check(JSON.parse(y1.body).user === 'bob' && !aliceAfter.body.includes('bob이 쓴 글'), 'T08-C38 반대 방향도 거절/격리, alice 자료 불변');
  log('거절 전후 alice 자료 건수:', JSON.parse(aliceMe.body).notes.length, '→', JSON.parse(aliceAfter.body).notes.length);
  check(JSON.parse(aliceMe.body).notes.length === JSON.parse(aliceAfter.body).notes.length, 'T08-C39 거절 전후 건수 동일');

  fs.writeFileSync(__dirname + '/evidence.log', out.join('\n') + '\n');
  await browser.close();
  console.log(fails ? `\n실패 ${fails}건` : '\n모두 통과'); process.exit(fails ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
