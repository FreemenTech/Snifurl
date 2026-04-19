/* ============================================================
   SNIFURL — Frontend Logic
   ============================================================ */

const ICON = name => `<img src="/static/icons/${name}.svg" width="15" height="15" class="svg-icon" alt="${name}" />`;

// ---- PARTICLES ----
(function initParticles() {
  const canvas = document.getElementById('particles');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resize);
  resize();

  for (let i = 0; i < 60; i++) {
    particles.push({
      x: Math.random() * 1920,
      y: Math.random() * 1080,
      r: Math.random() * 1.2 + 0.2,
      vx: (Math.random() - 0.5) * 0.25,
      vy: -Math.random() * 0.3 - 0.05,
      alpha: Math.random() * 0.4 + 0.05,
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 212, 255, ${p.alpha})`;
      ctx.fill();
      p.x += p.vx; p.y += p.vy;
      if (p.y < -5) { p.y = H + 5; p.x = Math.random() * W; }
      if (p.x < -5) p.x = W + 5;
      if (p.x > W + 5) p.x = -5;
    });
    requestAnimationFrame(draw);
  }
  draw();
})();

// ---- KEYBOARD ----
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

// ---- EXAMPLES ----
function setExample(url) {
  document.getElementById('urlInput').value = url;
  document.getElementById('urlInput').focus();
}

// ---- STATE ----
let scanning = false;

// ---- SCAN ----
async function startScan() {
  if (scanning) return;
  const input = document.getElementById('urlInput');
  const url = input.value.trim();

  if (!url) {
    shakeInput();
    return;
  }

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
  const delays = [300, 600, 1000, 1400];

  for (let i = 0; i < steps.length; i++) {
    await sleep(delays[i] - (i > 0 ? delays[i-1] : 0));
    const el = document.getElementById(steps[i]);
    if (el) {
      el.classList.add('active');
      el.querySelector('.step-dot').classList.add('active');
      if (i > 0) {
        const prev = document.getElementById(steps[i-1]);
        if (prev) {
          prev.classList.remove('active');
          prev.classList.add('done');
          prev.querySelector('.step-dot').classList.remove('active');
          prev.querySelector('.step-dot').classList.add('done');
        }
      }
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
    if (el) {
      el.classList.remove('active','done');
      el.querySelector('.step-dot').classList.remove('active','done');
    }
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

  animateScore(score, level);

  const badge   = document.getElementById('riskBadge');
  const riskIcon = document.getElementById('riskIcon');
  const riskText = document.getElementById('riskText');

  badge.className = 'risk-badge ' + levelToClass(level);
  riskIcon.innerHTML = levelToIcon(level);
  riskText.textContent = level;

  document.getElementById('recommendationText').textContent = reco.replace(/^[\S]+\s/, '');
  document.getElementById('analyzedUrl').textContent = data.url || '';

  buildIndicators(ind);
  buildLog(details);
  buildInfoCards(ind);

  setTimeout(() => {
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);
}

// ---- ANIMATE SCORE ----
function animateScore(target, level) {
  const numEl    = document.getElementById('scoreNumber');
  const gaugeArc = document.getElementById('gaugeArc');
  const totalLen = 251;

  let current = 0;
  const duration = 900;
  const start = performance.now();

  numEl.style.color = levelToColor(level);

  function tick(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);

    current = Math.round(eased * target);
    numEl.textContent = current;

    const len = (current / 100) * totalLen;
    gaugeArc.style.strokeDasharray = `${len} ${totalLen}`;

    const gradId = target >= 75 ? 'gaugeGradDanger' : target >= 35 ? 'gaugeGradMed' : 'gaugeGradSafe';
    gaugeArc.setAttribute('stroke', `url(#${gradId})`);

    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ---- BUILD INDICATORS ----
function buildIndicators(ind) {
  const grid = document.getElementById('indicatorsGrid');
  grid.innerHTML = '';

  const items = [
    {
      name:   'HTTPS',
      value:  ind.uses_https ? 'Enabled' : 'Disabled',
      icon:   ind.uses_https ? ICON('lock') : ICON('lock-open'),
      status: ind.uses_https ? 'ok' : 'bad',
    },
    {
      name:   'DNS',
      value:  ind.dns_exists === true ? 'Resolved' : ind.dns_exists === false ? 'Unresolved' : 'Unknown',
      icon:   ind.dns_exists ? ICON('globe') : ICON('x'),
      status: ind.dns_exists ? 'ok' : ind.dns_exists === false ? 'bad' : 'neutral',
    },
    {
      name:   'DIRECT IP',
      value:  ind.has_ip ? 'Detected' : 'None',
      icon:   ind.has_ip ? ICON('server') : ICON('check'),
      status: ind.has_ip ? 'bad' : 'ok',
    },
    {
      name:   'URL SHORTENER',
      value:  ind.is_url_shortener ? 'Yes' : 'No',
      icon:   ind.is_url_shortener ? ICON('link') : ICON('check'),
      status: ind.is_url_shortener ? 'warn' : 'ok',
    },
    {
      name:   'SUSPICIOUS TLD',
      value:  ind.suspicious_tld ? '.' + ind.suspicious_tld : 'Normal',
      icon:   ind.suspicious_tld ? ICON('flag') : ICON('check'),
      status: ind.suspicious_tld ? 'bad' : 'ok',
    },
    {
      name:   'SUBDOMAINS',
      value:  ind.nb_subdomains != null ? String(ind.nb_subdomains) : '—',
      icon:   ind.nb_subdomains >= 3 ? ICON('triangle-alert') : ICON('layers'),
      status: ind.nb_subdomains >= 3 ? 'warn' : ind.nb_subdomains >= 1 ? 'neutral' : 'ok',
    },
    {
      name:   'RECENT DOMAIN',
      value:  ind.recently_created === true ? 'Yes (<30d)' : ind.recently_created === false ? 'No' : 'Unknown',
      icon:   ind.recently_created ? ICON('triangle-alert') : ICON('calendar'),
      status: ind.recently_created ? 'bad' : ind.recently_created === false ? 'ok' : 'neutral',
    },
    {
      name:   '@ CHARACTER',
      value:  ind.has_at_char ? 'Present' : 'Absent',
      icon:   ind.has_at_char ? ICON('at-sign') : ICON('check'),
      status: ind.has_at_char ? 'bad' : 'ok',
    },
    {
      name:   'DOUBLE EXT.',
      value:  ind.double_extension ? 'Detected' : 'None',
      icon:   ind.double_extension ? ICON('mail-warning') : ICON('check'),
      status: ind.double_extension ? 'bad' : 'ok',
    },
    {
      name:   'HOMOGRAPHS',
      value:  ind.homograph_chars && ind.homograph_chars.length ? ind.homograph_chars.join(' ') : 'None',
      icon:   ind.homograph_chars && ind.homograph_chars.length ? ICON('scan') : ICON('check'),
      status: ind.homograph_chars && ind.homograph_chars.length ? 'bad' : 'ok',
    },
    {
      name:   'SPOOFED BRAND',
      value:  ind.brand_in_subdomain && ind.brand_in_subdomain.length ? ind.brand_in_subdomain.join(', ') : 'None',
      icon:   ind.brand_in_subdomain && ind.brand_in_subdomain.length ? ICON('building-2') : ICON('check'),
      status: ind.brand_in_subdomain && ind.brand_in_subdomain.length ? 'bad' : 'ok',
    },
    {
      name:   'URL LENGTH',
      value:  ind.length != null ? ind.length + ' chars' : '—',
      icon:   ind.length > 100 ? ICON('ruler') : ICON('ruler'),
      status: ind.length > 120 ? 'warn' : 'neutral',
    },
  ];

  items.forEach((item, i) => {
    const card = document.createElement('div');
    card.className = `indicator-card ${item.status}`;
    card.style.animationDelay = `${i * 40}ms`;
    card.innerHTML = `
      <span class="indicator-icon">${item.icon}</span>
      <div class="indicator-info">
        <div class="indicator-name">${item.name}</div>
        <div class="indicator-value">${item.value}</div>
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
    log.innerHTML = '<div style="color:var(--text-dim);font-size:12px">No details available.</div>';
    return;
  }

  details.forEach((line, i) => {
    const isPlus  = line.includes('(+');
    const isMinus = line.includes('(-') || line.includes('floor score');
    const div = document.createElement('div');
    div.className = 'log-line';
    div.style.animationDelay = `${i * 30}ms`;
    div.innerHTML = `
      <span class="log-marker ${isPlus ? 'log-plus' : isMinus ? 'log-minus' : 'log-neutral'}">
        ${isPlus ? ICON('triangle-alert') : isMinus ? ICON('check') : ICON('minus')}
      </span>
      <span class="log-content">${escHtml(line)}</span>
    `;
    log.appendChild(div);
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
    <div class="info-card-title">${ICON('shield')} SSL CERTIFICATE</div>
    ${infoRow('Valid',       ssl.valid === true ? 'Yes' : ssl.valid === false ? 'No' : 'Unknown', ssl.valid === true ? 'ok' : ssl.valid === false ? 'bad' : '')}
    ${infoRow('CN',          ssl.subject_cn || '—')}
    ${infoRow('Issuer',      ssl.issuer_org || '—')}
    ${infoRow('Self-signed', ssl.self_signed === true ? 'Yes' : ssl.self_signed === false ? 'No' : '—', ssl.self_signed ? 'bad' : 'ok')}
    ${infoRow('Expires',     ssl.expires ? ssl.expires.split(' ').slice(0,4).join(' ') : '—')}
    ${ssl.error ? infoRow('Error', ssl.error, 'warn') : ''}
  `;
  container.appendChild(sslCard);

  const whois = ind.whois || {};
  const whoisCard = document.createElement('div');
  whoisCard.className = 'info-card';
  const ageDays = whois.age_days;
  const ageStr  = ageDays != null ? `${ageDays} day${ageDays > 1 ? 's' : ''}` : '—';
  const ageClass = ageDays != null ? (ageDays < 30 ? 'bad' : ageDays < 365 ? 'warn' : 'ok') : '';
  whoisCard.innerHTML = `
    <div class="info-card-title">${ICON('database')} WHOIS</div>
    ${infoRow('Domain',     whois.domain || '—')}
    ${infoRow('Registrar',  whois.registrar ? truncate(whois.registrar, 28) : '—')}
    ${infoRow('Creation',   whois.creation_date ? whois.creation_date.split(' ')[0] : '—')}
    ${infoRow('Age',        ageStr, ageClass)}
    ${infoRow('Expiration', whois.expiration_date ? whois.expiration_date.split(' ')[0] : '—')}
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
  document.getElementById('urlInput').value = '';
  document.getElementById('urlInput').focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ---- HELPERS ----
function show(id) { const el = document.getElementById(id); if (el) el.style.display = ''; }
function hide(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

function shakeInput() {
  const wrap = document.getElementById('inputWrapper');
  wrap.classList.add('error');
  setTimeout(() => wrap.classList.remove('error'), 600);
}

function levelToClass(level) {
  const map = { 'SAFE': 'safe', 'LOW': 'low', 'MEDIUM': 'medium', 'HIGH': 'high', 'CRITICAL': 'critical' };
  return map[level] || 'neutral';
}

function levelToIcon(level) {
  const map = {
    'SAFE':     ICON('shield-check-green'),
    'LOW':      ICON('shield'),
    'MEDIUM':   ICON('triangle-alert'),
    'HIGH':     ICON('shield-alert'),
    'CRITICAL': ICON('siren'),
  };
  return map[level] || ICON('shield');
}

function levelToColor(level) {
  const map = {
    'SAFE':     '#00ff9d',
    'LOW':      '#00d4ff',
    'MEDIUM':   '#ffcc00',
    'HIGH':     '#ff8800',
    'CRITICAL': '#ff2d55',
  };
  return map[level] || '#e0eeff';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}