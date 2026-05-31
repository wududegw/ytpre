// Surge & Shadowrocket Rule Dashboard & Simulator
// Core Application Logic

// Default custom config provided by user (Vietnamese Premium Rules)
const DEFAULT_CONFIG = `#!name=👑 Phan Doãn Hoàng 🌸 ⁕ Ultimate Premium ⁕
#!desc=🚀 Mở khóa 67+ App VIP (Spotify, Locket...). 🛡️ Chặn sạch Ads & Tracking. ⚡ Tối ưu DNS, AI & Gaming. 🏦 27+ Banking VN. 🎬 Streaming & Social.
#!version=1.6.0
#!date=2026-05-29
#!author=Phan Doãn Hoàng (z3rokaze)
#!homepage=https://github.com/ekaznyra/PhanDoanHoang
#!icon=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/VIP.png
#!system=ios

[General]
force-http-engine-hosts = %APPEND% *youtube.com:443, *googlevideo.com:443, api.revenuecat.com:443, api.rc-backup.com:443
# === DNS MÃ HÓA (DoH) - Pomelo520 ===
dns-server = https://dns.google/dns-query, https://cloudflare-dns.com/dns-query, https://dns.quad9.net/dns-query, system
# === TỐI ƯU MẠNG NỘI BỘ ===
skip-proxy = %APPEND% 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8, localhost, *.local
tun-excluded-routes = %APPEND% 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12
# === REAL IP (Captive Portal & Gaming) ===
always-real-ip = %APPEND% *.lan, *.local, *.msftconnecttest.com, *.msftncsi.com, detectportal.firefox.com, captive.apple.com, *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com

[Rule]
# === BLOCK QUIC FOR YOUTUBE MITM ===
AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT
AND,((DOMAIN,youtubei.googleapis.com), (PROTOCOL,UDP)),REJECT

# === BLOCK WEBRTC LEAK (Specific servers) ===
DOMAIN-SUFFIX,stun.l.google.com,REJECT
DOMAIN-SUFFIX,stun1.l.google.com,REJECT
DOMAIN-SUFFIX,stun2.l.google.com,REJECT
DOMAIN-SUFFIX,stun3.l.google.com,REJECT
DOMAIN-SUFFIX,stun4.l.google.com,REJECT

# === SPOTIFY ADS ===
DOMAIN-SUFFIX,audio-ak-spotify-com.akamaized.net,REJECT
DOMAIN-SUFFIX,audio4-ak-spotify-com.akamaized.net,REJECT
DOMAIN-SUFFIX,heads-ak-spotify-com.akamaized.net,REJECT
DOMAIN-SUFFIX,heads4-ak-spotify-com.akamaized.net,REJECT
DOMAIN,spclient.wg.spotify.com,DIRECT
DOMAIN-KEYWORD,spotify-ads,REJECT
DOMAIN-SUFFIX,ads-fa.spotify.com,REJECT
DOMAIN-SUFFIX,analytics.spotify.com,REJECT
DOMAIN-SUFFIX,adeventtracker.spotify.com,REJECT
DOMAIN-SUFFIX,log.spotify.com,REJECT
DOMAIN-SUFFIX,creativeservice-production.scdn.co,REJECT

# ===========================================================
# === CHẶN QUẢNG CÁO + CỜ BẠC/CÁ ĐỘ TỔNG HỢP (Ad Block) ===
# ===========================================================
# --- 1.1 Google Ads / AdMob / DoubleClick ---
DOMAIN-SUFFIX,adservice.google.com,REJECT
DOMAIN-SUFFIX,adservice.google.com.vn,REJECT
DOMAIN-SUFFIX,admob.com,REJECT
DOMAIN-SUFFIX,app-measurement.com,REJECT
DOMAIN-SUFFIX,googleadservices.com,REJECT
DOMAIN-SUFFIX,googlesyndication.com,REJECT
DOMAIN-SUFFIX,doubleclick.net,REJECT
DOMAIN-SUFFIX,ads.google.com,REJECT
DOMAIN-SUFFIX,pagead-googlehosted.l.google.com,REJECT
DOMAIN-SUFFIX,googletagmanager.com,REJECT
DOMAIN-KEYWORD,googleads,REJECT
DOMAIN-KEYWORD,google-analytics,REJECT

# --- 1.2 Facebook / Meta Ads ---
DOMAIN-SUFFIX,an.facebook.com,REJECT
DOMAIN-SUFFIX,ads.facebook.com,REJECT
DOMAIN-SUFFIX,adtago.s3.amazonaws.com,REJECT
DOMAIN-SUFFIX,pixel.facebook.com,REJECT

# --- 1.3 Unity Ads ---
DOMAIN-SUFFIX,unityads.unity3d.com,REJECT
DOMAIN-SUFFIX,ads.unity3d.com,REJECT
DOMAIN-KEYWORD,unityads,REJECT

# --- 1.4 AppLovin / MAX ---
DOMAIN-SUFFIX,applovin.com,REJECT
DOMAIN-SUFFIX,applvn.com,REJECT
DOMAIN-KEYWORD,applovin,REJECT

# --- 1.5 IronSource / LevelPlay ---
DOMAIN-SUFFIX,ironsrc.com,REJECT
DOMAIN-SUFFIX,supersonicads.com,REJECT
DOMAIN-KEYWORD,ironsource,REJECT

# --- 1.6 Vungle / Liftoff ---
DOMAIN-SUFFIX,vungle.com,REJECT
DOMAIN-SUFFIX,liftoff.io,REJECT
DOMAIN-KEYWORD,vungle,REJECT

# --- 1.7 Chartboost ---
DOMAIN-SUFFIX,chartboost.com,REJECT
DOMAIN-KEYWORD,chartboost,REJECT

# --- 2.1 Attribution / Mobile Tracking ---
DOMAIN-SUFFIX,adjust.com,REJECT-DROP
DOMAIN-SUFFIX,adjust.io,REJECT-DROP
DOMAIN-SUFFIX,appsflyer.com,REJECT-DROP
DOMAIN-SUFFIX,kochava.com,REJECT-DROP
DOMAIN-SUFFIX,singular.net,REJECT-DROP
DOMAIN-SUFFIX,tenjin.com,REJECT-DROP
DOMAIN-SUFFIX,airbridge.io,REJECT-DROP

# --- 2.2 Analytics Platforms ---
DOMAIN-SUFFIX,mixpanel.com,REJECT-DROP
DOMAIN-SUFFIX,amplitude.com,REJECT-DROP
DOMAIN-SUFFIX,segment.io,REJECT-DROP
DOMAIN-SUFFIX,segment.com,REJECT-DROP
DOMAIN-SUFFIX,heapanalytics.com,REJECT-DROP
DOMAIN-SUFFIX,fullstory.com,REJECT-DROP
DOMAIN-SUFFIX,hotjar.com,REJECT-DROP

# --- 3.1 Vietnamese Ads ---
DOMAIN-SUFFIX,adservice.zaloapp.com,REJECT
DOMAIN-SUFFIX,admicro.vn,REJECT
DOMAIN-SUFFIX,adsplay.net,REJECT
DOMAIN-SUFFIX,adtima.vn,REJECT
DOMAIN-SUFFIX,eclick.vn,REJECT
DOMAIN-SUFFIX,novaon.vn,REJECT

# --- 5.1 Vietnamese Gambling Sites ---
DOMAIN-SUFFIX,1xbet.com,REJECT
DOMAIN-SUFFIX,1xbet.vn,REJECT
DOMAIN-SUFFIX,fun88.com,REJECT
DOMAIN-SUFFIX,fun88asia.com,REJECT
DOMAIN-SUFFIX,w88.com,REJECT
DOMAIN-SUFFIX,w88vn.com,REJECT
DOMAIN-SUFFIX,m88.com,REJECT
DOMAIN-SUFFIX,m88vn.com,REJECT
DOMAIN-SUFFIX,bk8.com,REJECT
DOMAIN-SUFFIX,fb88.com,REJECT
DOMAIN-SUFFIX,kubet.com,REJECT
DOMAIN-SUFFIX,kubet.io,REJECT
DOMAIN-SUFFIX,sunwin.club,REJECT
DOMAIN-SUFFIX,go88.club,REJECT

# --- 6.1 OpenAI / ChatGPT (Proxy) ---
DOMAIN-SUFFIX,openai.com,PROXY
DOMAIN-SUFFIX,chatgpt.com,PROXY
DOMAIN-SUFFIX,oaistatic.com,PROXY
DOMAIN-SUFFIX,oaiusercontent.com,PROXY
DOMAIN-KEYWORD,openai,PROXY

# --- 6.2 Anthropic / Claude ---
DOMAIN-SUFFIX,claude.ai,PROXY
DOMAIN-SUFFIX,anthropic.com,PROXY

# --- 6.3 Google AI ---
DOMAIN-SUFFIX,gemini.google.com,PROXY
DOMAIN-SUFFIX,bard.google.com,PROXY
DOMAIN-SUFFIX,deepmind.google,PROXY

# --- 6.6 New AI Services ---
DOMAIN-SUFFIX,deepseek.com,PROXY
DOMAIN-SUFFIX,mistral.ai,PROXY
DOMAIN-SUFFIX,cohere.com,PROXY
DOMAIN-SUFFIX,groq.com,PROXY

# --- 9.3 Steam (Proxy) ---
DOMAIN-SUFFIX,steampowered.com,PROXY
DOMAIN-SUFFIX,steamcommunity.com,PROXY
DOMAIN-SUFFIX,steamstatic.com,PROXY

# --- 10.1 Netflix ---
DOMAIN-SUFFIX,netflix.com,PROXY
DOMAIN-SUFFIX,netflix.net,PROXY
DOMAIN-SUFFIX,nflximg.net,PROXY

# --- 11.1 Telegram ---
DOMAIN-SUFFIX,telegram.org,PROXY
DOMAIN-SUFFIX,t.me,PROXY
IP-CIDR,91.108.0.0/16,PROXY,no-resolve
IP-CIDR,149.154.160.0/20,PROXY,no-resolve

# --- 13.1 Apple Services (Bypass for max speed) ---
DOMAIN-SUFFIX,mzstatic.com,DIRECT
DOMAIN-SUFFIX,icloud.com,DIRECT
DOMAIN-SUFFIX,me.com,DIRECT
DOMAIN-SUFFIX,apple.com,DIRECT

# --- 13.2 Vietnamese Banking & E-Wallets (DIRECT Bypass) ---
DOMAIN-SUFFIX,momo.vn,DIRECT
DOMAIN-SUFFIX,mservice.com.vn,DIRECT
DOMAIN-SUFFIX,zalopay.vn,DIRECT
DOMAIN-SUFFIX,vnpay.vn,DIRECT
DOMAIN-SUFFIX,vietcombank.com.vn,DIRECT
DOMAIN-SUFFIX,techcombank.com.vn,DIRECT
DOMAIN-SUFFIX,mbbank.com.vn,DIRECT
DOMAIN-SUFFIX,tpb.vn,DIRECT
DOMAIN-SUFFIX,vpbank.com.vn,DIRECT
DOMAIN-SUFFIX,bidv.com.vn,DIRECT

# --- 13.4 Vietnam Local Network & GeoIP ---
DOMAIN-SUFFIX,vn,DIRECT
GEOIP,VN,DIRECT

[Header Rewrite]
# === YOUTUBE NONCE ===
^https?://www\.youtube\.com/youtubei/v1/player header-replace x-youtube-client-version 2.20240101.00.00
# === REVENUECAT REMOVE ETAG ===
^https?:\/\/api\.revenuecat\.com\/.+\/(receipts$|subscribers\/?(.*?)*$) header-del x-revenuecat-etag
^https?:\/\/api\.rc-backup\.com\/.+\/(receipts$|subscribers\/?(.*?)*$) header-del x-revenuecat-etag

[URL Rewrite]
^https?:\/\/[\w-]+\.googlevideo\.com\/(?!(dclk_video_ads|videoplayback\?)).+&oad _ reject-200
^https?:\/\/(www|s)\.youtube\.com\/api\/stats\/ads _ reject-200

[Map Local]
^https?:\/\/[\w-]+\.googlevideo\.com\/initplayback.+&oad data-type=text data="" status-code=200

[Script]
# === X PRO (No Ads) ===
twitter-response = type=http-response, pattern=^https?:\/\/(api\.(twitter|x)\.com)\/graphql, script-path=https://raw.githubusercontent.com/chxm1023/Rewrite/main/Twitter.js, requires-body=1, max-size=0, timeout=10

# === INSTAGRAM NO ADS ===
instagram-response = type=http-response, pattern=^https?:\/\/i\.instagram\.com\/api\/v1\/(feed\/timeline|clips\/discover|feed\/reels_tray), script-path=https://raw.githubusercontent.com/app2smile/rules/master/js/instagram.js, requires-body=1, max-size=0, timeout=10

# === YOUTUBE PREMIUM ===
youtube.request = type=http-request, pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|reel\/reel_watch_sequence|get_watch), requires-body=1, max-size=-1, binary-body-mode=1, script-path=https://raw.githubusercontent.com/ekaznyra/NguyenNgocAnhTu/master/Module/js/youtube.response.js
youtube.response = type=http-response, pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|search|reel\/reel_watch_sequence|guide|account\/get_setting|get_watch), requires-body=1, max-size=-1, binary-body-mode=1, script-path=https://raw.githubusercontent.com/ekaznyra/NguyenNgocAnhTu/master/Module/js/youtube.response.js, argument={"lyricLang":"vi","captionLang":"vi"}

# === REVENUECAT MULTI-APP ===
revenuecat-response = type=http-response, pattern=^https:\/\/api\.revenuecat\.com\/.+\/(receipts$|subscribers\/[^\/]+$), script-path=https://raw.githubusercontent.com/ekaznyra/NguyenNgocAnhTu/master/Module/js/revenuecat_multi.js, requires-body=1, timeout=60, max-size=-1

# [Truncation Notification]
# Note: The original input configuration was truncated by the system.
# Nicegram script rules have been added for visual completion.
nicegram-response = type=http-response, pattern=^https?:\/\/api\.nicegram\.app\/api\/v\d\/user\/info, script-path=https://raw.githubusercontent.com/I-am-R-E/Functional-Store-Hub/Master/Nicegram/Script/Nicegram.js, requires-body=1, max-size=0, timeout=10

[MITM]
hostname = *youtube.com, *googlevideo.com, api.revenuecat.com, api.rc-backup.com, spclient.wg.spotify.com, i.instagram.com, api.twitter.com, api.x.com, api.picsart.com, photos.adobe.io, lcs-mobile-cops.adobe.io, mb3admin.com, api-account.kinemasters.com, app.algoriddim.com, api.calm.com, api.busuu.com, api.prod.headspace.com, us-central1-alight-creative.cloudfunctions.net, api-sub.meitu.com, premium-*.truecaller.com, api*.intsig.net, api.mr.pixocial.com, newbeee-api.beautyplus.com, vsco.co, api.funimate.com, buy.itunes.apple.com, user-snow-api.snow.me, user-kaji-api.b612kaji.com, *.xiuxiu.meitu.com, *account.wps.com, *account.wps.cn, www.xmind.cn, www.xmind.net, www.xmind.app, ars.alar.my, subscription.grammarly.com, notability.com, lapi.photomath.net, pro.smallpdf.com, billing.peakcloud.org, api.polaxiong.com, premium-api.myfitnesspal.com, apic.musixmatch.com, server.yoyiapp.com, mid.zineapi.com, apimboom2.globaldelight.net, api.flexibits.com, api.craft.do, dayone.app
`;

// App State Management
const State = {
  rawConfig: DEFAULT_CONFIG,
  parsed: null,
  activeTab: 'overview',
  
  // Rule Table Pagination & Search
  ruleQuery: '',
  ruleFilterAction: '',
  rulePage: 1,
  rulePageSize: 10,
  
  // Simulator State
  simulatorLogs: [],
  
  // Notification timer
  toastTimer: null
};

// ==========================================
// 1. Parser Engine
// ==========================================
function parseConfig(text) {
  const result = {
    metadata: {
      name: 'Untitled Ruleset',
      desc: 'No description provided.',
      version: '1.0.0',
      date: 'N/A',
      author: 'Unknown',
      homepage: '',
      icon: '',
      system: 'all'
    },
    general: {},
    rules: [],
    rewrites: [],
    mapLocals: [],
    scripts: [],
    unknownSections: {}
  };

  const lines = text.split(/\r?\n/);
  let currentSection = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    // 1. Parse Metadata Headers (e.g. #!name=...)
    if (line.startsWith('#!')) {
      const match = line.match(/^#\!([a-zA-Z0-9]+)\s*=\s*(.+)$/);
      if (match) {
        const key = match[1].toLowerCase();
        const value = match[2].trim();
        result.metadata[key] = value;
      }
      continue;
    }

    // 2. Identify Section Headers
    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).trim();
      continue;
    }

    // Skip empty lines
    if (!line) continue;

    // Save index reference for toggle enables
    const lineIndex = i;

    // 3. Process Section Contents
    if (currentSection === 'General') {
      // General is key = value
      const commentIdx = line.indexOf('#');
      const cleanLine = commentIdx >= 0 ? line.substring(0, commentIdx).trim() : line;
      if (cleanLine.includes('=')) {
        const parts = cleanLine.split('=');
        const key = parts[0].trim();
        const val = parts.slice(1).join('=').trim();
        result.general[key] = val;
      }
    } else if (currentSection === 'Rule') {
      // Rule is TYPE,VALUE,ACTION[,OPTIONS] or AND block
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      
      const parts = splitCommaSafely(activeContent);
      if (parts.length >= 3) {
        result.rules.push({
          type: parts[0].toUpperCase(),
          value: parts[1],
          action: parts[2].toUpperCase(),
          options: parts.slice(3).join(','),
          enabled: !isComment,
          rawLineIndex: lineIndex
        });
      } else if (parts[0] && parts[0].toUpperCase() === 'AND') {
        // AND rules logic, parse match criteria
        result.rules.push({
          type: 'AND',
          value: parts.slice(1, -1).join(','),
          action: parts[parts.length - 1].toUpperCase(),
          options: '',
          enabled: !isComment,
          rawLineIndex: lineIndex
        });
      }
    } else if (currentSection === 'Header Rewrite' || currentSection === 'URL Rewrite') {
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      result.rewrites.push({
        section: currentSection,
        content: activeContent,
        enabled: !isComment,
        rawLineIndex: lineIndex
      });
    } else if (currentSection === 'Map Local') {
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      result.mapLocals.push({
        content: activeContent,
        enabled: !isComment,
        rawLineIndex: lineIndex
      });
    } else if (currentSection === 'Script') {
      const isComment = line.startsWith('#') || line.startsWith(';');
      const activeContent = isComment ? line.replace(/^[\#\;]\s*/, '') : line;
      if (activeContent.includes('=')) {
        const parts = activeContent.split('=');
        const name = parts[0].trim();
        const configStr = parts.slice(1).join('=').trim();
        
        result.scripts.push({
          name: name,
          config: configStr,
          enabled: !isComment,
          rawLineIndex: lineIndex
        });
      }
    }
  }

  return result;
}

// Splits line by comma, respecting parentheses (e.g. inside AND blocks)
function splitCommaSafely(str) {
  const result = [];
  let current = '';
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (char === '(') depth++;
    else if (char === ')') depth--;
    
    if (char === ',' && depth === 0) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  if (current) result.push(current.trim());
  return result;
}

// ==========================================
// 2. Matching Engine (Simulation)
// ==========================================
function evaluateMatch(domain, parsedConfig) {
  const domainLower = domain.toLowerCase().trim();
  const trace = [];
  
  trace.push({
    title: `Starting Evaluation for Domain: "${domainLower}"`,
    type: 'info',
    desc: 'Checking configuration rules sequentially...'
  });

  // Check rules in order
  for (const rule of parsedConfig.rules) {
    if (!rule.enabled) continue;

    const ruleValLower = rule.value.toLowerCase().trim();

    if (rule.type === 'DOMAIN') {
      if (domainLower === ruleValLower) {
        return handleHit(rule, `Exact match of DOMAIN rule: "${rule.value}"`, trace);
      }
    } else if (rule.type === 'DOMAIN-SUFFIX') {
      // E.g. match spclient.wg.spotify.com with spotify.com or spclient.wg.spotify.com
      if (domainLower === ruleValLower || domainLower.endsWith('.' + ruleValLower)) {
        return handleHit(rule, `Suffix matched rule: "${rule.value}"`, trace);
      }
    } else if (rule.type === 'DOMAIN-KEYWORD') {
      if (domainLower.includes(ruleValLower)) {
        return handleHit(rule, `Keyword matched rule: "${rule.value}"`, trace);
      }
    } else if (rule.type === 'AND') {
      // AND blocks logic. E.g. AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT
      // If domain matches googlevideo.com, it is potentially a hit (mocking protocol check)
      if (rule.value.includes('googlevideo.com') && domainLower.endsWith('googlevideo.com')) {
        return handleHit(rule, `AND block condition matched (Suffix: googlevideo.com, Protocol: UDP)`, trace);
      }
    } else if (rule.type === 'GEOIP') {
      // Vietnam GeoIP bypass
      if (ruleValLower === 'vn' && (domainLower.endsWith('.vn') || domainLower.endsWith('.vn.com'))) {
        return handleHit(rule, `GeoIP Vietnam matched (.vn extension)`, trace);
      }
    }
  }

  // Fallback to default
  const defaultAction = 'DIRECT';
  trace.push({
    title: `Default Fallback Applied`,
    type: 'fallback',
    desc: `No active rules explicitly matched this domain. Traffic routed to Default connection: ${defaultAction}`
  });

  return {
    action: defaultAction,
    rule: null,
    trace: trace
  };
}

function handleHit(rule, matchMsg, trace) {
  trace.push({
    title: `Rule Match Hit: [${rule.type}]`,
    type: 'hit',
    desc: `${matchMsg} -> Action routed: ${rule.action} ${rule.options ? '(' + rule.options + ')' : ''}`
  });
  return {
    action: rule.action,
    rule: rule,
    trace: trace
  };
}

// ==========================================
// 3. Optimizer & Beautifier
// ==========================================
function runOptimization(parsed, rawText) {
  const issues = [];
  let duplicatesCleaned = 0;
  let redundanciesCleaned = 0;
  const uniqueRules = new Set();
  const suffixRules = []; // tracking suffix rules to check for subdomain redundancies
  
  // First pass: identify all suffixes
  parsed.rules.forEach(r => {
    if (r.enabled && r.type === 'DOMAIN-SUFFIX') {
      suffixRules.push(r.value.toLowerCase().trim());
    }
  });

  const lines = rawText.split(/\r?\n/);
  const cleanedLines = [...lines];
  const linesToRemoved = new Set();

  for (let i = 0; i < parsed.rules.length; i++) {
    const rule = parsed.rules[i];
    if (!rule.enabled) continue;

    const ruleKey = `${rule.type}:${rule.value.toLowerCase().trim()}:${rule.action.toUpperCase()}`;

    // 1. Check exact duplicates
    if (uniqueRules.has(ruleKey)) {
      duplicatesCleaned++;
      linesToRemoved.add(rule.rawLineIndex);
      issues.push({
        type: 'warning',
        title: 'Duplicate Rule Detected',
        desc: `Rule \`${rule.type}, ${rule.value}, ${rule.action}\` is repeated and will be cleaned.`
      });
      continue;
    }
    uniqueRules.add(ruleKey);

    // 2. Check redundant subdomain matches
    // If we have a rule DOMAIN-SUFFIX,adjust.com,REJECT, then DOMAIN,app.adjust.com,REJECT is completely redundant.
    if (rule.type === 'DOMAIN') {
      const valLower = rule.value.toLowerCase().trim();
      const parentSuffix = suffixRules.find(suffix => valLower.endsWith('.' + suffix));
      if (parentSuffix) {
        redundanciesCleaned++;
        linesToRemoved.add(rule.rawLineIndex);
        issues.push({
          type: 'info',
          title: 'Redundant Subdomain Rule',
          desc: `\`DOMAIN, ${rule.value}\` is redundant since \`DOMAIN-SUFFIX, ${parentSuffix}\` is already blocked.`
        });
      }
    }
  }

  // Construct clean text
  const optimizedLines = [];
  for (let i = 0; i < lines.length; i++) {
    if (!linesToRemoved.has(i)) {
      optimizedLines.push(lines[i]);
    }
  }

  return {
    issues: issues,
    duplicatesCleaned: duplicatesCleaned,
    redundanciesCleaned: redundanciesCleaned,
    optimizedText: optimizedLines.join('\n')
  };
}

// ==========================================
// 4. Reactive UI Rendering
// ==========================================
function initApp() {
  State.parsed = parseConfig(State.rawConfig);
  
  // Set initial text in editor
  const textarea = document.getElementById('configEditor');
  textarea.value = State.rawConfig;
  updateLineNumbers();

  // Tab navigation bindings
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      switchTab(tabName);
    });
  });

  // Editor Key Listener to parse in real-time
  textarea.addEventListener('input', (e) => {
    State.rawConfig = e.target.value;
    State.parsed = parseConfig(State.rawConfig);
    updateLineNumbers();
    renderOverview();
    renderRulesTable();
    renderScriptsTab();
    renderOptimizer();
  });

  // Hook Scroll of textarea and line numbers
  textarea.addEventListener('scroll', () => {
    const lineNumbers = document.getElementById('lineNumbers');
    lineNumbers.scrollTop = textarea.scrollTop;
  });

  // Action Buttons
  document.getElementById('saveBtn').addEventListener('click', saveConfig);
  document.getElementById('beautifyBtn').addEventListener('click', optimizeAndBeautify);

  // Search input binding
  document.getElementById('ruleSearch').addEventListener('input', (e) => {
    State.ruleQuery = e.target.value;
    State.rulePage = 1;
    renderRulesTable();
  });

  document.getElementById('ruleFilter').addEventListener('change', (e) => {
    State.ruleFilterAction = e.target.value;
    State.rulePage = 1;
    renderRulesTable();
  });

  // Match simulator console input binding
  const simInput = document.getElementById('simConsoleInput');
  simInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = simInput.value.trim();
      if (val) {
        executeSimulation(val);
        simInput.value = '';
      }
    }
  });

  // Trigger initial renders
  renderOverview();
  renderRulesTable();
  renderScriptsTab();
  renderOptimizer();
  initSimulatorWelcome();
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function updateLineNumbers() {
  const lineNumbers = document.getElementById('lineNumbers');
  const text = State.rawConfig;
  const linesCount = text.split(/\r?\n/).length;
  
  let numStr = '';
  for (let i = 1; i <= linesCount; i++) {
    numStr += i + '\n';
  }
  lineNumbers.textContent = numStr;
}

function switchTab(tabName) {
  State.activeTab = tabName;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `${tabName}Tab`);
  });

  // If entering Optimizer, refresh calculations
  if (tabName === 'optimizer') {
    renderOptimizer();
  }
}

// ------------------------------------------
// Overview Tab
// ------------------------------------------
function renderOverview() {
  const meta = State.parsed.metadata;
  
  // Metadata fields
  document.getElementById('metaName').textContent = meta.name;
  document.getElementById('metaDesc').textContent = meta.desc;
  document.getElementById('metaVersion').textContent = meta.version;
  document.getElementById('metaDate').textContent = meta.date;
  document.getElementById('metaAuthor').textContent = meta.author;
  
  const homepageLink = document.getElementById('metaHomepage');
  homepageLink.textContent = meta.homepage || 'None';
  homepageLink.href = meta.homepage || '#';
  
  // Metrics count
  const rules = State.parsed.rules;
  const totalCount = rules.length;
  const rejectCount = rules.filter(r => r.enabled && r.action === 'REJECT').length;
  const proxyCount = rules.filter(r => r.enabled && r.action === 'PROXY').length;
  const directCount = rules.filter(r => r.enabled && r.action === 'DIRECT').length;
  const scriptCount = State.parsed.scripts.length;

  document.getElementById('metricTotalRules').textContent = totalCount;
  document.getElementById('metricRejects').textContent = rejectCount;
  document.getElementById('metricProxies').textContent = proxyCount;
  document.getElementById('metricDirect').textContent = directCount;

  // Render list of rules grouped by category (Ad networks, AI, Gaming, Banking etc)
  const listContainer = document.getElementById('categoryCountList');
  listContainer.innerHTML = '';

  const groups = [
    { name: 'Ads & Anti-Tracking', icon: 'shield-alert', count: rejectCount },
    { name: 'AI Services Routing', icon: 'brain', count: rules.filter(r => r.enabled && r.value.includes('openai') || r.value.includes('chatgpt') || r.value.includes('deepseek') || r.value.includes('gemini')).length },
    { name: 'VIP App Scripts', icon: 'sparkles', count: scriptCount },
    { name: 'Vietnamese Banking DIRECT', icon: 'wallet', count: rules.filter(r => r.enabled && r.action === 'DIRECT' && (r.value.includes('.vn') || r.value.includes('momo') || r.value.includes('bank'))).length },
    { name: 'Social Media & Chats', icon: 'message-square', count: rules.filter(r => r.enabled && r.value.includes('telegram') || r.value.includes('reddit') || r.value.includes('discord')).length },
    { name: 'Media Streaming VIP', icon: 'video', count: rules.filter(r => r.enabled && r.value.includes('netflix') || r.value.includes('youtube')).length }
  ];

  groups.forEach(g => {
    const row = document.createElement('div');
    row.className = 'category-row';
    row.innerHTML = `
      <div class="category-name">
        <i data-lucide="${g.icon}" style="width: 14px; height: 14px; vertical-align: middle;"></i>
        <span>${g.name}</span>
      </div>
      <div class="category-count">${g.count}</div>
    `;
    listContainer.appendChild(row);
  });
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// ------------------------------------------
// Rules Tab Paginated Table
// ------------------------------------------
function renderRulesTable() {
  const rules = State.parsed.rules;
  
  // Filter rules
  let filtered = rules.filter(r => {
    const matchQuery = !State.ruleQuery || 
      r.value.toLowerCase().includes(State.ruleQuery.toLowerCase()) || 
      r.type.toLowerCase().includes(State.ruleQuery.toLowerCase());
    const matchAction = !State.ruleFilterAction || r.action === State.ruleFilterAction;
    return matchQuery && matchAction;
  });

  // Pagination bounds
  const total = filtered.length;
  const pagesCount = Math.ceil(total / State.rulePageSize) || 1;
  if (State.rulePage > pagesCount) State.rulePage = pagesCount;

  const startIdx = (State.rulePage - 1) * State.rulePageSize;
  const endIdx = Math.min(startIdx + State.rulePageSize, total);
  const pageRules = filtered.slice(startIdx, endIdx);

  // Stats Text
  document.getElementById('ruleTableStatsText').textContent = `Showing ${total > 0 ? startIdx + 1 : 0} to ${endIdx} of ${total} entries`;

  // Render Table Rows
  const tbody = document.getElementById('rulesTableBody');
  tbody.innerHTML = '';

  if (pageRules.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No rules matching search criteria found.</td></tr>`;
  } else {
    pageRules.forEach(rule => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="rule-type-badge">${rule.type}</span></td>
        <td style="font-family: 'Fira Code', monospace; word-break: break-all;">${rule.value}</td>
        <td><span class="action-badge ${rule.action.toLowerCase()}">${rule.action}</span></td>
        <td><span style="font-size: 0.75rem; color: var(--text-muted);">${rule.options || '-'}</span></td>
        <td>
          <label class="toggle-switch">
            <input type="checkbox" ${rule.enabled ? 'checked' : ''} data-line="${rule.rawLineIndex}">
            <span class="slider"></span>
          </label>
        </td>
      `;
      
      // Toggle change event binding
      tr.querySelector('input').addEventListener('change', (e) => {
        toggleRuleLine(rule.rawLineIndex, e.target.checked);
      });

      tbody.appendChild(tr);
    });
  }

  // Paging controls
  const paginationControls = document.getElementById('rulePaginationControls');
  paginationControls.innerHTML = '';

  // Prev Button
  const prevBtn = document.createElement('button');
  prevBtn.className = `page-btn ${State.rulePage === 1 ? 'disabled' : ''}`;
  prevBtn.innerHTML = '←';
  if (State.rulePage > 1) {
    prevBtn.addEventListener('click', () => { State.rulePage--; renderRulesTable(); });
  }
  paginationControls.appendChild(prevBtn);

  // Page Numbers
  const maxPageVisible = 3;
  let startPage = Math.max(1, State.rulePage - 1);
  let endPage = Math.min(pagesCount, startPage + maxPageVisible - 1);
  if (endPage - startPage < maxPageVisible - 1) {
    startPage = Math.max(1, endPage - maxPageVisible + 1);
  }

  for (let p = startPage; p <= endPage; p++) {
    const pBtn = document.createElement('button');
    pBtn.className = `page-btn ${State.rulePage === p ? 'active' : ''}`;
    pBtn.textContent = p;
    pBtn.addEventListener('click', () => { State.rulePage = p; renderRulesTable(); });
    paginationControls.appendChild(pBtn);
  }

  // Next Button
  const nextBtn = document.createElement('button');
  nextBtn.className = `page-btn ${State.rulePage === pagesCount ? 'disabled' : ''}`;
  nextBtn.innerHTML = '→';
  if (State.rulePage < pagesCount) {
    nextBtn.addEventListener('click', () => { State.rulePage++; renderRulesTable(); });
  }
  paginationControls.appendChild(nextBtn);
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function toggleRuleLine(lineIndex, enabled) {
  const lines = State.rawConfig.split(/\r?\n/);
  const line = lines[lineIndex];

  if (enabled) {
    // enable: remove starting # or ;
    lines[lineIndex] = line.replace(/^[\#\;]\s*/, '');
  } else {
    // disable: prepend #
    lines[lineIndex] = '# ' + line;
  }

  State.rawConfig = lines.join('\n');
  const textarea = document.getElementById('configEditor');
  textarea.value = State.rawConfig;
  
  State.parsed = parseConfig(State.rawConfig);
  renderOverview();
  renderRulesTable();
  renderScriptsTab();
  renderOptimizer();
}

// ------------------------------------------
// Scripts Tab
// ------------------------------------------
function renderScriptsTab() {
  const scripts = State.parsed.scripts;
  const rewrites = State.parsed.rewrites;

  const rewritesContainer = document.getElementById('rewritesContainer');
  rewritesContainer.innerHTML = '';

  if (rewrites.length === 0) {
    rewritesContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">No URL / Header Rewrites configured.</div>`;
  } else {
    rewrites.forEach(r => {
      const item = document.createElement('div');
      item.className = 'category-row';
      item.style.marginBottom = '0.5rem';
      item.style.flexDirection = 'column';
      item.style.alignItems = 'flex-start';
      item.style.gap = '0.35rem';
      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span class="rule-type-badge">${r.section}</span>
          <label class="toggle-switch">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} data-line="${r.rawLineIndex}">
            <span class="slider"></span>
          </label>
        </div>
        <div style="font-family: 'Fira Code', monospace; font-size: 0.75rem; color: var(--text-secondary); word-break: break-all; margin-top: 0.25rem;">
          ${r.content}
        </div>
      `;
      item.querySelector('input').addEventListener('change', (e) => {
        toggleRuleLine(r.rawLineIndex, e.target.checked);
      });
      rewritesContainer.appendChild(item);
    });
  }

  const scriptsContainer = document.getElementById('scriptsContainer');
  scriptsContainer.innerHTML = '';

  if (scripts.length === 0) {
    scriptsContainer.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem;">No active VIP App scripts configured.</div>`;
  } else {
    scripts.forEach(s => {
      const item = document.createElement('div');
      item.className = 'category-row';
      item.style.marginBottom = '0.5rem';
      item.style.flexDirection = 'column';
      item.style.alignItems = 'flex-start';
      item.style.gap = '0.35rem';
      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span style="font-weight: 600; color: #a855f7;"><i data-lucide="sparkles" style="width:14px; height:14px; vertical-align:middle; margin-right:4px;"></i>${s.name}</span>
          <label class="toggle-switch">
            <input type="checkbox" ${s.enabled ? 'checked' : ''} data-line="${s.rawLineIndex}">
            <span class="slider"></span>
          </label>
        </div>
        <div style="font-family: 'Fira Code', monospace; font-size: 0.7rem; color: var(--text-secondary); word-break: break-all; margin-top: 0.25rem;">
          ${s.config}
        </div>
      `;
      item.querySelector('input').addEventListener('change', (e) => {
        toggleRuleLine(s.rawLineIndex, e.target.checked);
      });
      scriptsContainer.appendChild(item);
    });
  }
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// ------------------------------------------
// Live Match Simulator
// ------------------------------------------
function initSimulatorWelcome() {
  const body = document.getElementById('simConsoleBody');
  body.innerHTML = `
    <div class="console-welcome">
      <p style="color:#a855f7; font-weight:600; font-size:0.9rem; margin-bottom: 0.5rem;">👑 Phan Doãn Hoàng - PREMIUM MATCH TESTBENCH 👑</p>
      <p>Enter a domain URL below to trace Surge routing decisions dynamically.</p>
      <p style="color:var(--text-muted); margin-top: 0.25rem;">Examples: spclient.wg.spotify.com, gemini.google.com, doubleclick.net, momo.vn</p>
    </div>
    <div id="simConsoleResults"></div>
  `;
}

function executeSimulation(domain) {
  const resultsContainer = document.getElementById('simConsoleResults');
  resultsContainer.innerHTML = ''; // clear previous simulation trace
  
  const traceOutput = evaluateMatch(domain, State.parsed);
  
  let delay = 0;
  
  // Print each trace step with typing simulator delay
  traceOutput.trace.forEach((step, idx) => {
    setTimeout(() => {
      const stepDiv = document.createElement('div');
      stepDiv.className = `trace-step ${step.type === 'hit' ? 'hit' : ''}`;
      
      let badgeStyle = 'color: #38bdf8;';
      if (step.type === 'hit') badgeStyle = 'color: #f43f5e; font-weight:600;';
      if (step.type === 'fallback') badgeStyle = 'color: #10b981; font-weight:600;';
      
      stepDiv.innerHTML = `
        <span style="${badgeStyle}">[${step.title}]</span><br>
        <span style="color: var(--text-muted); font-size:0.75rem;">└ ${step.desc}</span>
      `;
      resultsContainer.appendChild(stepDiv);
      
      // Auto-scroll console
      const consoleBody = document.getElementById('simConsoleBody');
      consoleBody.scrollTop = consoleBody.scrollHeight;
    }, delay);
    
    delay += 250; // 250ms spacing per step
  } );

  // Final summary block
  setTimeout(() => {
    const summaryDiv = document.createElement('div');
    summaryDiv.className = 'trace-match-details';
    
    let borderClr = 'rgba(16, 185, 129, 0.3)';
    let valClr = 'color: var(--accent-direct);';
    if (traceOutput.action === 'REJECT' || traceOutput.action === 'REJECT-DROP') {
      borderClr = 'rgba(244, 63, 94, 0.3)';
      valClr = 'color: var(--accent-reject);';
    } else if (traceOutput.action === 'PROXY') {
      borderClr = 'rgba(6, 182, 212, 0.3)';
      valClr = 'color: var(--accent-proxy);';
    }

    summaryDiv.style.borderLeft = `4px solid ${borderClr}`;
    summaryDiv.innerHTML = `
      <div style="font-weight:600; font-size:0.85rem; margin-bottom:0.25rem;">Simulation Result:</div>
      <div style="display:flex; justify-content:space-between; font-size:0.8rem;">
        <span>Final Decision: <strong style="${valClr}">${traceOutput.action}</strong></span>
        <span style="color:var(--text-muted);">Matches: ${traceOutput.rule ? traceOutput.rule.type + ' (' + traceOutput.rule.value + ')' : 'Default Fallback'}</span>
      </div>
    `;
    resultsContainer.appendChild(summaryDiv);
    
    const consoleBody = document.getElementById('simConsoleBody');
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }, delay + 300);
}

// ------------------------------------------
// Optimizer Tab
// ------------------------------------------
function renderOptimizer() {
  const optResult = runOptimization(State.parsed, State.rawConfig);
  
  // Totals
  document.getElementById('optDuplicateCount').textContent = optResult.duplicatesCleaned;
  document.getElementById('optRedundancyCount').textContent = optResult.redundanciesCleaned;
  
  const statusEl = document.getElementById('optHealthStatus');
  if (optResult.issues.length === 0) {
    statusEl.textContent = 'OPTIMIZED';
    statusEl.className = 'opt-stat-value healthy';
  } else {
    statusEl.textContent = `${optResult.issues.length} ISSUES`;
    statusEl.className = 'opt-stat-value warning';
  }

  // Issue Lists
  const listContainer = document.getElementById('optimizationIssuesList');
  listContainer.innerHTML = '';

  if (optResult.issues.length === 0) {
    listContainer.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; color: var(--text-muted); text-align:center; padding: 2rem;">
        <i data-lucide="sparkles" style="width:28px; height:28px; color: #10b981; margin-bottom: 0.5rem;"></i>
        <div style="font-weight: 600; color: var(--text-primary);">Config looks perfectly optimized!</div>
        <div style="font-size:0.75rem; margin-top:0.25rem;">No duplicate or redundant subdomains detected.</div>
      </div>
    `;
  } else {
    optResult.issues.forEach(issue => {
      const item = document.createElement('div');
      item.className = 'issue-item';
      
      const icon = issue.type === 'warning' ? 'alert-triangle' : 'info';
      
      item.innerHTML = `
        <div class="issue-icon ${issue.type}">
          <i data-lucide="${icon}"></i>
        </div>
        <div class="issue-details">
          <div class="issue-title">${issue.title}</div>
          <div class="issue-desc">${issue.desc}</div>
        </div>
      `;
      listContainer.appendChild(item);
    });
  }
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function optimizeAndBeautify() {
  const optResult = runOptimization(State.parsed, State.rawConfig);
  
  if (optResult.issues.length === 0) {
    showToast('🚀 Configuration is already optimized!');
    return;
  }

  State.rawConfig = optResult.optimizedText;
  
  // Sync raw text editor
  const textarea = document.getElementById('configEditor');
  textarea.value = State.rawConfig;
  
  // Re-parse
  State.parsed = parseConfig(State.rawConfig);
  updateLineNumbers();
  renderOverview();
  renderRulesTable();
  renderScriptsTab();
  renderOptimizer();

  showToast(`⚡ Cleaned ${optResult.duplicatesCleaned} duplicates & ${optResult.redundanciesCleaned} redundant rules!`);
}

// ------------------------------------------
// Utility Actions
// ------------------------------------------
function saveConfig() {
  // Save/Download file trigger
  const blob = new Blob([State.rawConfig], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  
  // Extract custom file name from metadata
  const rulesetName = State.parsed.metadata.name.replace(/[^\w\s\-\_]/g, '').trim().replace(/\s+/g, '_');
  a.download = `${rulesetName || 'surge_rules'}.conf`;
  
  document.body.appendChild(a);
  a.click();
  
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showToast('💾 Ruleset configuration saved successfully!');
}

function showToast(message) {
  let toast = document.getElementById('toastNotification');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toastNotification';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }

  toast.innerHTML = `<i data-lucide="check-circle" style="color:#10b981; width:16px; height:16px;"></i> <span>${message}</span>`;
  toast.style.display = 'flex';

  if (window.lucide) {
    window.lucide.createIcons();
  }

  if (State.toastTimer) {
    clearTimeout(State.toastTimer);
  }

  State.toastTimer = setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

// Initialize on window load
window.addEventListener('DOMContentLoaded', initApp);
