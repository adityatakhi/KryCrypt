/* =========================================
   KeyCrypt — app.js
   All password/passphrase generation uses crypto.getRandomValues
   Nothing is ever sent to a server.
   ========================================= */

'use strict';

// ---- Word list for passphrases (EFF short-ish, curated 200 words) ----
const WORDLIST = [
  'apple','arrow','badge','baker','beach','bells','black','blade','blast','bloom',
  'blown','board','brain','brave','break','brick','bride','brief','bring','broad',
  'broke','brook','brown','brush','build','bulge','burst','cable','camel','candy',
  'cargo','cedar','chair','chalk','chest','chief','child','chill','chips','civic',
  'claim','clasp','class','clean','clear','click','cliff','cloud','clove','coast',
  'cobra','comic','coral','couch','court','cover','craft','crane','crash','cream',
  'creek','crisp','cross','crown','crush','crust','curve','cycle','daisy','dance',
  'debut','delta','dense','depot','depth','derby','draft','drain','drake','drama',
  'drape','drawn','dream','drift','drink','drive','drown','drums','dryer','eagle',
  'early','earth','eight','ember','empty','ended','enjoy','entry','equal','event',
  'every','exact','exist','extra','fable','faced','fancy','fence','fetch','fever',
  'field','final','first','fixed','flame','flask','fleck','fleet','flesh','flint',
  'flood','flora','flour','flute','focal','forge','forth','forum','found','foxes',
  'fresh','front','frost','fruit','fully','funny','gavel','ghost','glade','gland',
  'glare','glass','glide','globe','gloom','gloss','glove','glyph','gnome','grace',
  'grade','grain','grand','grant','grape','grasp','grass','gravel','great','green',
  'greet','grind','groan','groom','grove','guard','guava','guild','guise','gusto',
  'hazel','heist','helix','helps','herbs','hinge','hippo','hoist','honor','human',
  'humid','ideal','image','inbox','inner','input','inter','inward','ivory','jazzy',
  'jewel','jumpy','kayak','kelvin','knack','kneel','knife','knoll','known','kraft',
  'label','lance','laser','latch','layer','leach','learn','ledge','lemon','level',
  'light','limit','linen','liner','lingo','lived','llama','lobby','local','lodge',
  'logic','loner','lotus','lowly','lucid','lumpy','lusty','lyric','magic','major',
  'maker','manor','maple','march','match','maxim','melon','mercy','merit','metal',
  'micro','might','mines','minor','minus','mixed','model','mogul','moose','moral',
  'mossy','motel','motor','motto','mount','moved','mural','music','naive','naval',
  'nerve','nexus','night','ninja','noble','north','noted','novel','nymph','oaken',
  'occur','ocean','offer','onset','orbit','order','outdo','oven','oxide','ozone',
  'paddy','paint','panel','paper','patch','pause','peach','pearl','pedal','penny',
  'phase','phone','photo','piano','pilot','pinch','pixel','pizza','pivot','pixel',
  'place','plain','plane','plant','plate','plaza','pluck','plume','plunk','polar',
  'poppy','porch','pouch','power','press','price','pride','privy','prize','probe',
  'proof','prose','proud','proxy','prune','pulse','punch','pupil','purge','puzzled',
  'query','quest','quick','quiet','quota','quote','rabbi','radar','radio','rainy',
  'rally','ranch','range','rapid','raven','reach','ready','realm','rebel','recap',
  'relay','remix','repay','reset','rider','ridge','risky','rival','rivet','robot',
  'rocky','rouge','round','rover','rowdy','royal','runic','rusty','sadly','saint',
  'salve','sandy','sauce','savvy','scald','scala','scene','scone','score','scout',
  'screw','sedan','seeds','seize','serum','setup','seven','shaft','shake','shame',
  'shape','shark','sharp','shelf','shell','shift','shirt','shock','shore','short',
  'shout','sigma','siren','sixth','skate','skill','skimp','skull','slate','sleet',
  'slice','slick','slide','slope','smart','smell','smile','smock','smoke','smolt',
  'snail','snake','snowy','solar','solid','solve','sorry','south','space','spare',
  'spark','spawn','speed','spice','spike','spine','spite','split','spoke','spray',
  'squad','staff','stage','stain','stale','stalk','stamp','stand','stark','start',
  'stash','state','stead','steal','steam','steel','steep','steer','stern','stick',
  'stiff','still','stock','stomp','stone','stood','store','storm','story','stout',
  'straw','strip','strum','stuck','study','style','suave','sugar','suite','super',
  'surge','swamp','swarm','swear','sweep','swift','swirl','sword','syrup','tabby',
  'tally','tango','taunt','tempo','tense','tepid','terra','thick','think','third',
  'thorn','three','threw','thyme','tidal','tiger','tilde','timer','tinge','titan',
  'token','today','tonal','toner','topic','torch','total','touch','tough','towel',
  'tower','toxic','trace','track','trade','trail','train','trait','tramp','trap',
  'trend','tribe','trick','tried','trout','trace','truck','tuned','turbo','twist',
  'ultra','under','unify','unity','until','upend','upper','upset','urban','usage',
  'valve','vapor','vault','vigor','viral','visor','visit','vivid','vocal','voter',
  'wafer','waltz','watch','weave','wedge','wheat','wheel','where','which','while',
  'white','whole','width','windy','witty','woman','woven','young','zenith','zones'
];

// ---- State ----
const state = {
  mode: 'password',   // 'password' | 'passphrase'
  opts: { upper: true, lower: true, nums: true, syms: true, noamb: false, norep: false },
  length: 16,
  ppWords: 4,
  ppSep: 'hyphen',
  ppCapitalize: false,
  ppIncludeNum: true,
  lastPw: '',
  history: []
};

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const NUMS  = '0123456789';
const SYMS  = '!@#$%^&*()-_=+[]{};:,.<>?';
const AMB   = new Set(['0','O','l','I','1']);

const PRESETS = {
  pin:        { len: 6,  upper: false, lower: false, nums: true,  syms: false, noamb: false, norep: false },
  wifi:       { len: 12, upper: true,  lower: true,  nums: true,  syms: false, noamb: true,  norep: false },
  standard:   { len: 16, upper: true,  lower: true,  nums: true,  syms: true,  noamb: false, norep: false },
  strong:     { len: 24, upper: true,  lower: true,  nums: true,  syms: true,  noamb: false, norep: false },
  max:        { len: 48, upper: true,  lower: true,  nums: true,  syms: true,  noamb: false, norep: true  },
};

const SEP_MAP = {
  hyphen:  '-',
  dot:     '.',
  under:   '_',
  space:   ' ',
  none:    '',
  random:  null   // chosen per-word
};
const SEP_RANDOMS = ['-', '.', '_', '~', '!', '#', '@'];

// ---- Charset builder ----
function buildCharset() {
  let c = '';
  if (state.opts.upper) c += UPPER;
  if (state.opts.lower) c += LOWER;
  if (state.opts.nums)  c += NUMS;
  if (state.opts.syms)  c += SYMS;
  if (state.opts.noamb) c = [...c].filter(ch => !AMB.has(ch)).join('');
  return c;
}

// ---- Cryptographic random sampling ----
function secureSample(charset, len, noRepeat) {
  if (!charset.length) return '';
  const result = [];
  const used = new Set();
  let buf = new Uint32Array(len * 3);
  crypto.getRandomValues(buf);
  let idx = 0;

  while (result.length < len) {
    if (idx >= buf.length) {
      buf = new Uint32Array(len * 3);
      crypto.getRandomValues(buf);
      idx = 0;
    }
    const ch = charset[buf[idx++] % charset.length];
    if (noRepeat && used.has(ch)) continue;
    used.add(ch);
    result.push(ch);
  }
  return result.join('');
}

// ---- Passphrase generation ----
function secureRandomInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

function generatePassphrase() {
  const wordCount = state.ppWords;
  const words = [];
  const used = new Set();

  for (let i = 0; i < wordCount; i++) {
    let word;
    do {
      word = WORDLIST[secureRandomInt(WORDLIST.length)];
    } while (used.has(word));
    used.add(word);

    if (state.ppCapitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    words.push(word);
  }

  // Build passphrase with separators
  let result;
  if (state.ppSep === 'random') {
    result = words.reduce((acc, w, i) => {
      if (i === 0) return w;
      const sep = SEP_RANDOMS[secureRandomInt(SEP_RANDOMS.length)];
      return acc + sep + w;
    }, '');
  } else {
    const sep = SEP_MAP[state.ppSep];
    result = words.join(sep);
  }

  // Optionally append a random number
  if (state.ppIncludeNum) {
    const num = secureRandomInt(9000) + 1000; // 4-digit number
    const sep = state.ppSep === 'none' ? '' : (SEP_MAP[state.ppSep] || '-');
    result += sep + num;
  }

  return result;
}

function passphraseEntropy() {
  // log2(WORDLIST.length ^ words) + optional number bits
  const wordBits = Math.round(state.ppWords * Math.log2(WORDLIST.length));
  const numBits  = state.ppIncludeNum ? Math.round(Math.log2(9000)) : 0;
  return wordBits + numBits;
}

// ---- Entropy / stats ----
function calcEntropy(charsetSize, length) {
  if (charsetSize === 0) return 0;
  return Math.round(length * Math.log2(charsetSize));
}

function crackTime(bits) {
  const gps = 1e12;
  const secs = Math.pow(2, bits) / gps;
  if (secs < 1)        return '< 1 sec';
  if (secs < 60)       return Math.round(secs) + ' sec';
  if (secs < 3600)     return Math.round(secs / 60) + ' min';
  if (secs < 86400)    return Math.round(secs / 3600) + ' hrs';
  if (secs < 2628000)  return Math.round(secs / 86400) + ' days';
  if (secs < 31536000) return Math.round(secs / 2628000) + ' months';
  if (secs < 3.154e10) return Math.round(secs / 31536000) + ' yrs';
  if (secs < 3.154e13) return (secs / 3.154e10).toFixed(1) + 'K yrs';
  if (secs < 3.154e16) return (secs / 3.154e13).toFixed(1) + 'M yrs';
  if (secs < 3.154e19) return (secs / 3.154e16).toFixed(1) + 'B yrs';
  return '∞';
}

function strengthInfo(bits) {
  if (bits < 28)  return { label: 'Very weak',   pct: 8,   color: '#f85149' };
  if (bits < 40)  return { label: 'Weak',         pct: 22,  color: '#f85149' };
  if (bits < 60)  return { label: 'Fair',         pct: 42,  color: '#d29922' };
  if (bits < 80)  return { label: 'Good',         pct: 62,  color: '#3fb950' };
  if (bits < 100) return { label: 'Strong',       pct: 80,  color: '#0ea5e9' };
  return              { label: 'Very strong',  pct: 100, color: '#0ea5e9' };
}

// ---- Coloured password display ----
function coloredHtml(pw) {
  return [...pw].map(ch => {
    if (UPPER.includes(ch)) return `<span class="c-upper">${ch}</span>`;
    if (NUMS.includes(ch))  return `<span class="c-num">${ch}</span>`;
    if (SYMS.includes(ch))  return `<span class="c-sym">${ch}</span>`;
    return ch;
  }).join('');
}

// ---- Passphrase colored display ----
function passphraseHtml(pp) {
  const sep = state.ppSep === 'space' ? ' '
            : state.ppSep === 'none'  ? null
            : null; // for 'random' or structured sep, we detect them

  // Split on any known separator characters to colorize words vs separators
  const parts = pp.split(/([^a-zA-Z0-9])/);
  return parts.map(part => {
    if (/^[a-zA-Z]+$/.test(part)) return `<span class="c-word">${part}</span>`;
    if (/^[0-9]+$/.test(part))    return `<span class="c-num">${part}</span>`;
    if (part.length > 0)          return `<span class="c-sep">${part}</span>`;
    return '';
  }).join('');
}

// ---- Master generate ----
function generate() {
  if (state.mode === 'passphrase') {
    generatePassphraseMode();
  } else {
    generatePasswordMode();
  }
}

function generatePasswordMode() {
  const charset = buildCharset();
  if (!charset) {
    document.getElementById('pw-display').textContent = 'Enable at least one character type';
    return;
  }

  const pw = secureSample(charset, state.length, state.opts.norep);
  state.lastPw = pw;

  document.getElementById('pw-display').innerHTML = coloredHtml(pw);

  const bits = calcEntropy(charset.length, state.length);
  updateStrengthUI('s-bar', 's-label', 's-entropy', 's-crack', 's-charset',
    bits, charset.length + ' chars');

  addToHistory(pw, bits, strengthInfo(bits).label, strengthInfo(bits).color, 'password');
}

function generatePassphraseMode() {
  const pp = generatePassphrase();
  state.lastPw = pp;

  document.getElementById('pw-display').innerHTML = passphraseHtml(pp);

  const bits = passphraseEntropy();
  const wordInfo = state.ppWords + ' words';
  updateStrengthUI('s-bar', 's-label', 's-entropy', 's-crack', 's-charset',
    bits, wordInfo);

  addToHistory(pp, bits, strengthInfo(bits).label, strengthInfo(bits).color, 'passphrase');
}

function updateStrengthUI(barId, labelId, entropyId, crackId, charsetId, bits, charsetText) {
  const si = strengthInfo(bits);
  const bar = document.getElementById(barId);
  bar.style.width      = si.pct + '%';
  bar.style.background = si.color;

  document.getElementById(labelId).textContent = si.label;
  document.getElementById(labelId).style.color = si.color;
  document.getElementById(entropyId).textContent = bits + ' bits';
  document.getElementById(crackId).textContent   = crackTime(bits);
  document.getElementById(charsetId).textContent = charsetText;
}

// ---- Mode switcher ----
function switchMode(mode) {
  state.mode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
  document.getElementById('password-options').style.display = mode === 'password' ? '' : 'none';
  document.getElementById('passphrase-options').style.display = mode === 'passphrase' ? '' : 'none';
  generate();
}

// ---- Toggle option ----
function toggle(key) {
  state.opts[key] = !state.opts[key];
  const btn = document.getElementById('t-' + key);
  btn.classList.toggle('on', state.opts[key]);
  if (state.lastPw) generate();
}

// ---- Length ----
function onLengthChange(val) {
  state.length = parseInt(val, 10);
  document.getElementById('len-display').textContent = val;
  if (state.lastPw) generate();
}

// ---- Passphrase controls ----
function onWordCountChange(val) {
  state.ppWords = parseInt(val, 10);
  document.getElementById('pp-word-display').textContent = val;
  if (state.lastPw) generate();
}

function onSepChange(val) {
  state.ppSep = val;
  if (state.lastPw) generate();
}

function onCapChange(checked) {
  state.ppCapitalize = checked;
  if (state.lastPw) generate();
}

function onNumChange(checked) {
  state.ppIncludeNum = checked;
  if (state.lastPw) generate();
}

// ---- Presets ----
function applyPreset(name) {
  // Switch to password mode when using these presets
  if (state.mode !== 'password') switchMode('password');

  const p = PRESETS[name];
  state.length = p.len;

  document.getElementById('len-slider').value = p.len;
  document.getElementById('len-display').textContent = p.len;

  const keys = ['upper','lower','nums','syms','noamb','norep'];
  keys.forEach(k => {
    state.opts[k] = p[k];
    document.getElementById('t-' + k).classList.toggle('on', p[k]);
  });

  document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
  event.currentTarget.classList.add('active');
  generate();
}

// ---- Copy ----
function copyPassword() {
  if (!state.lastPw) return;
  copyText(state.lastPw);
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard');
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Copied to clipboard');
  });
}

// ---- Toast ----
let toastTimer = null;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.childNodes[1].textContent = ' ' + msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2000);
}

// ---- History ----
function addToHistory(pw, bits, label, color, type) {
  state.history.unshift({ pw, bits, label, color, type, time: new Date().toLocaleTimeString() });
  if (state.history.length > 20) state.history.pop();
  renderHistory();
}

function renderHistory() {
  const el = document.getElementById('history-list');
  if (!state.history.length) {
    el.innerHTML = '<div class="history-empty">No passwords generated yet.</div>';
    return;
  }
  el.innerHTML = state.history.map((h, i) => `
    <div class="history-entry">
      <div class="hist-left">
        <span class="hist-type-badge hist-type-${h.type || 'password'}">${h.type === 'passphrase' ? 'phrase' : 'pw'}</span>
        <span class="hist-pw">${h.pw}</span>
      </div>
      <div class="hist-meta">
        <span class="hist-badge" style="color:${h.color};border-color:${h.color}30">${h.label}</span>
        <span>${h.bits}b</span>
        <span>${h.time}</span>
      </div>
      <button class="hist-copy" onclick="copyText(state.history[${i}].pw)" title="Copy">
        <svg viewBox="0 0 20 20" fill="none"><rect x="7" y="7" width="10" height="12" rx="2" stroke="currentColor" stroke-width="1.5"/><path d="M5 13H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="1.5"/></svg>
      </button>
    </div>
  `).join('');
}

function clearHistory() {
  state.history = [];
  renderHistory();
}

// ---- Tab navigation ----
document.querySelectorAll('.nav-item').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    const tabName = link.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    link.classList.add('active');
    document.getElementById('tab-' + tabName).classList.add('active');
  });
});

// ---- Strength checker tab ----
function analysePassword(val) {
  const row = document.getElementById('check-strength-row');
  const criteria = document.getElementById('check-criteria');

  if (!val) {
    row.style.opacity = '0';
    criteria.innerHTML = '';
    return;
  }

  row.style.opacity = '1';

  let pool = 0;
  if (/[a-z]/.test(val)) pool += 26;
  if (/[A-Z]/.test(val)) pool += 26;
  if (/[0-9]/.test(val)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(val)) pool += 32;

  const bits = pool > 0 ? Math.round(val.length * Math.log2(pool)) : 0;
  const si   = strengthInfo(bits);

  updateSegments('cs-segments', si.pct, si.color);
  document.getElementById('cs-label').textContent    = si.label;
  document.getElementById('cs-label').style.color    = si.color;
  document.getElementById('cs-entropy').textContent  = bits + ' bits';
  document.getElementById('cs-crack').textContent    = crackTime(bits);
  document.getElementById('cs-len').textContent      = val.length + ' chars';

  const checks = [
    { label: 'At least 12 characters',      pass: val.length >= 12 },
    { label: 'At least 16 characters',      pass: val.length >= 16 },
    { label: 'Contains uppercase letters',  pass: /[A-Z]/.test(val) },
    { label: 'Contains lowercase letters',  pass: /[a-z]/.test(val) },
    { label: 'Contains numbers',            pass: /[0-9]/.test(val) },
    { label: 'Contains special characters', pass: /[^a-zA-Z0-9]/.test(val) },
    { label: 'Over 60 bits of entropy',     pass: bits >= 60 },
    { label: 'Over 80 bits of entropy',     pass: bits >= 80 },
  ];

  criteria.innerHTML = checks.map(c => `
    <div class="criterion ${c.pass ? 'pass' : ''}">
      <span class="dot"></span>
      ${c.label}
    </div>
  `).join('');
}

function toggleEye() {
  const inp = document.getElementById('check-input');
  const showing = inp.type === 'text';
  inp.type = showing ? 'password' : 'text';
  document.getElementById('eye-icon').innerHTML = showing
    ? '<path d="M2 10s3-6 8-6 8 6 8 6-3 6-8 6-8-6-8-6z" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2.5" stroke="currentColor" stroke-width="1.5"/>'
    : '<path d="M3 3l14 14M6.5 6.6A6.9 6.9 0 0 0 2 10s3 6 8 6a6.9 6.9 0 0 0 4.2-1.4M9.5 5.1A6.2 6.2 0 0 1 10 5c5 0 8 5 8 5a12.7 12.7 0 0 1-1.7 2.3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>';
}

// ---- Init ----
renderHistory();
generate();
