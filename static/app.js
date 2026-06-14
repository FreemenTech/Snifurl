/* ============================================================
   SnifURL — Frontend logic
   ============================================================ */

// ---- SHARE ----
function shareResult() {
  const btnText = document.getElementById('shareBtnText');
  const score   = document.getElementById('scoreNumber').textContent;
  const level   = document.getElementById('riskText').textContent;
  const url     = document.getElementById('analyzedUrl').textContent;
  const reco    = document.getElementById('recommendationText').textContent;

  const indicators = [];
  document.querySelectorAll('.indicator-card.bad .indicator-name').forEach(el => {
    indicators.push(el.textContent.trim());
  });
  document.querySelectorAll('.indicator-card.warn .indicator-name').forEach(el => {
    indicators.push(el.textContent.trim());
  });

  const levelEmoji = {
    'SAFE': '✅', 'LOW': 'ℹ️', 'MEDIUM': '🔍', 'HIGH': '⚠️', 'CRITICAL': '🚨'
  }[level] || '🔍';

  const signalsLine = indicators.length
    ? `Signals : ${indicators.slice(0, 4).join(', ')}${indicators.length > 4 ? '…' : ''}`
    : 'Signals : None detected';

  const text = [
    `🔍 SnifURL Analysis — snifurl.online`,
    `URL     : ${url}`,
    `Score   : ${score}/100`,
    `Level   : ${level} ${levelEmoji}`,
    `Result  : ${reco}`,
    ``,
    signalsLine,
    `---`,
    `Analyzed with SnifURL → https://snifurl.online`
  ].join('\n');

  const flash = () => {
    btnText.textContent = 'Copied to clipboard';
    setTimeout(() => { btnText.textContent = 'Copy summary'; }, 2200);
  };

  navigator.clipboard.writeText(text).then(flash).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    flash();
  });
}

// ---- KEYBOARD ----
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

// ---- EXAMPLES ----
function setExample(url) {
  const input = document.getElementById('urlInput');
  input.value = url;
  input.focus();
}

// ---- STATE ----
let scanning = false;

// ---- SCAN ----
async function startScan() {
  if (scanning) return;
  const input = document.getElementById('urlInput');
  const url = input.value.trim();

  if (!url) { shakeInput(); return; }

  scanning = true;
  showLoader();

  try {
    await animateLoaderSteps();

    const res = await fetch('/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    showResults(data);

  } catch (err) {
    showError(err.message || 'Unable to contact server');
  } finally {
    scanning = false;
  }
}

// ---- LOADER STEPS ----
async function animateLoaderSteps() {
  const steps = ['step1', 'step2', 'step3', 'step4'];
  const delays = [250, 500, 850, 1150];

  for (let i = 0; i < steps.length; i++) {
    await sleep(delays[i] - (i > 0 ? delays[i-1] : 0));
    const el = document.getElementById(steps[i]);
    if (!el) continue;
    el.classList.add('active');
    if (i > 0) {
      const prev = document.getElementById(steps[i-1]);
      if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
    }
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---- SHOW LOADER ----
function showLoader() {
  hide('resultsSection');
  hide('errorSection');
  show('loaderSection');

  ['step1','step2','step3','step4'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('active','done');
  });

  document.getElementById('scanBtn').disabled = true;
}

// ---- SHOW RESULTS ----
function showResults(data) {
  hide('loaderSection');
  hide('errorSection');
  show('resultsSection');

  document.getElementById('scanBtn').disabled = false;

  const score   = data.score || 0;
  const level   = data.risk_level || 'SAFE';
  const reco    = data.recommendation || '';
  const details = data.details || [];
  const ind     = data.indicators || {};

  document.getElementById('scoreCard').setAttribute('data-level', level);

  animateScore(score);

  document.getElementById('riskText').textContent = level;
  document.getElementById('recommendationText').textContent =
    reco.replace(/^[^\w]+\s*/, '').trim() || '—';
  document.getElementById('analyzedUrl').textContent = data.url || '';

  buildIndicators(ind);
  buildLog(details);
  buildInfoCards(ind);

  setTimeout(() => {
    document.getElementById('resultsSection').scrollIntoView({
      behavior: 'smooth', block: 'start'
    });
  }, 60);
}

// ---- ANIMATE SCORE ----
function animateScore(target) {
  const numEl = document.getElementById('scoreNumber');
  const fillEl = document.getElementById('scoreTrackFill');

  fillEl.style.width = target + '%';

  let current = 0;
  const duration = 800;
  const start = performance.now();

  function tick(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    current = Math.round(eased * target);
    numEl.textContent = current;
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ---- BUILD INDICATORS ----
function buildIndicators(ind) {
  const grid = document.getElementById('indicatorsGrid');
  grid.innerHTML = '';

  const items = [
    { name: 'HTTPS',           value: ind.uses_https ? 'Enabled' : 'Disabled',
      status: ind.uses_https ? 'ok' : 'bad' },
    { name: 'DNS',             value: ind.dns_exists === true ? 'Resolved' : ind.dns_exists === false ? 'Unresolved' : 'Unknown',
      status: ind.dns_exists ? 'ok' : ind.dns_exists === false ? 'bad' : 'neutral' },
    { name: 'DIRECT IP',       value: ind.has_ip ? 'Detected' : 'None',
      status: ind.has_ip ? 'bad' : 'ok' },
    { name: 'URL SHORTENER',   value: ind.is_url_shortener ? 'Yes' : 'No',
      status: ind.is_url_shortener ? 'warn' : 'ok' },
    { name: 'SUSPICIOUS TLD',  value: ind.suspicious_tld ? '.' + ind.suspicious_tld : 'Normal',
      status: ind.suspicious_tld ? 'bad' : 'ok' },
    { name: 'SUBDOMAINS',      value: ind.nb_subdomains != null ? String(ind.nb_subdomains) : '—',
      status: ind.nb_subdomains >= 3 ? 'warn' : ind.nb_subdomains >= 1 ? 'neutral' : 'ok' },
    { name: 'RECENT DOMAIN',   value: ind.recently_created === true ? 'Yes (<30d)' : ind.recently_created === false ? 'No' : 'Unknown',
      status: ind.recently_created ? 'bad' : ind.recently_created === false ? 'ok' : 'neutral' },
    { name: '@ CHARACTER',     value: ind.has_at_char ? 'Present' : 'Absent',
      status: ind.has_at_char ? 'bad' : 'ok' },
    { name: 'DOUBLE EXTENSION',value: ind.double_extension ? 'Detected' : 'None',
      status: ind.double_extension ? 'bad' : 'ok' },
    { name: 'HOMOGRAPHS',      value: ind.homograph_chars && ind.homograph_chars.length ? ind.homograph_chars.join(' ') : 'None',
      status: ind.homograph_chars && ind.homograph_chars.length ? 'bad' : 'ok' },
    { name: 'SPOOFED BRAND',   value: ind.brand_in_subdomain && ind.brand_in_subdomain.length ? ind.brand_in_subdomain.join(', ') : 'None',
      status: ind.brand_in_subdomain && ind.brand_in_subdomain.length ? 'bad' : 'ok' },
    { name: 'URL LENGTH',      value: ind.length != null ? ind.length + ' chars' : '—',
      status: ind.length > 120 ? 'warn' : 'neutral' },
  ];

  items.forEach(item => {
    const card = document.createElement('div');
    card.className = `indicator-card ${item.status}`;
    card.innerHTML = `
      <span class="indicator-status"></span>
      <div class="indicator-info">
        <div class="indicator-name">${item.name}</div>
        <div class="indicator-value">${escHtml(item.value)}</div>
      </div>
    `;
    grid.appendChild(card);
  });
}

// ---- BUILD LOG ----
function buildLog(details) {
  const log = document.getElementById('detailsLog');
  log.innerHTML = '';

  if (!details || details.length === 0) {
    log.innerHTML = '<li><span class="log-content">No scoring details available.</span></li>';
    return;
  }

  details.forEach(line => {
    const isPlus  = line.includes('(+');
    const isMinus = line.includes('(-') || line.includes('floor score');
    const li = document.createElement('li');
    li.innerHTML = `
      <span class="log-marker ${isPlus ? 'log-plus' : isMinus ? 'log-minus' : 'log-neutral'}">${isPlus ? '+' : isMinus ? '−' : '•'}</span>
      <span class="log-content">${escHtml(line)}</span>
    `;
    log.appendChild(li);
  });
}

// ---- BUILD INFO CARDS ----
function buildInfoCards(ind) {
  const container = document.getElementById('infoCards');
  container.innerHTML = '';

  const ssl = ind.ssl_certificate || {};
  const sslCard = document.createElement('div');
  sslCard.className = 'info-card';
  sslCard.innerHTML = `
    <div class="info-card-title">SSL CERTIFICATE</div>
    ${infoRow('Valid',       ssl.valid === true ? 'Yes' : ssl.valid === false ? 'No' : 'Unknown',
              ssl.valid === true ? 'ok' : ssl.valid === false ? 'bad' : '')}
    ${infoRow('Common name', ssl.subject_cn || '—')}
    ${infoRow('Issuer',      ssl.issuer_org || '—')}
    ${infoRow('Self-signed', ssl.self_signed === true ? 'Yes' : ssl.self_signed === false ? 'No' : '—',
              ssl.self_signed ? 'bad' : 'ok')}
    ${infoRow('Expires',     ssl.expires ? ssl.expires.split(' ').slice(0,4).join(' ') : '—')}
    ${ssl.error ? infoRow('Error', ssl.error, 'warn') : ''}
  `;
  container.appendChild(sslCard);

  const whois = ind.whois || {};
  const ageDays = whois.age_days;
  const ageStr  = ageDays != null ? `${ageDays} day${ageDays > 1 ? 's' : ''}` : '—';
  const ageClass = ageDays != null
    ? (ageDays < 30 ? 'bad' : ageDays < 365 ? 'warn' : 'ok')
    : '';
  const whoisCard = document.createElement('div');
  whoisCard.className = 'info-card';
  whoisCard.innerHTML = `
    <div class="info-card-title">WHOIS</div>
    ${infoRow('Domain',     whois.domain || '—')}
    ${infoRow('Registrar',  whois.registrar ? truncate(whois.registrar, 28) : '—')}
    ${infoRow('Created',    whois.creation_date ? whois.creation_date.split(' ')[0] : '—')}
    ${infoRow('Age',        ageStr, ageClass)}
    ${infoRow('Expires',    whois.expiration_date ? whois.expiration_date.split(' ')[0] : '—')}
    ${infoRow('Country',    whois.country || '—')}
  `;
  container.appendChild(whoisCard);
}

function infoRow(key, val, cls = '') {
  return `<div class="info-row">
    <span class="info-key">${escHtml(key)}</span>
    <span class="info-val ${cls}">${escHtml(String(val))}</span>
  </div>`;
}

// ---- SHOW ERROR ----
function showError(msg) {
  hide('loaderSection');
  hide('resultsSection');
  show('errorSection');
  document.getElementById('errorMsg').textContent = msg;
  document.getElementById('scanBtn').disabled = false;
}

// ---- RESET ----
function resetScan() {
  hide('loaderSection');
  hide('resultsSection');
  hide('errorSection');
  scanning = false;
  document.getElementById('scanBtn').disabled = false;
  const input = document.getElementById('urlInput');
  input.value = '';
  input.focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ---- HELPERS ----
function show(id) { const el = document.getElementById(id); if (el) el.hidden = false; }
function hide(id) { const el = document.getElementById(id); if (el) el.hidden = true; }

function shakeInput() {
  const wrap = document.getElementById('inputWrapper');
  wrap.classList.add('error');
  setTimeout(() => wrap.classList.remove('error'), 600);
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}
