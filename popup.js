// popup.js - performs local URL analysis and updates UI
// No remote calls, no eval. All analysis is local.

const dom = id => document.getElementById(id);

const analyzeBtn = dom('analyze-btn');
const scanAgainBtn = dom('scan-again');
const highlightBtn = dom('highlight-btn');
const openSiteBtn = dom('open-site');
const currentUrlEl = dom('current-url');
const resultCard = dom('result-card');
const reasonsList = dom('reasons-list');
const gaugeFill = dom('gauge-fill');
const gaugeLabel = dom('gauge-label');
const riskLevelEl = dom('risk-level');
const riskDescEl = dom('risk-desc');
const statusBadge = dom('status-badge');

let currentUrl = '';

function setStatus(text){statusBadge.textContent = text}

function showUrl(url){
  currentUrl = url || '';
  currentUrlEl.textContent = currentUrl || '(no site detected)';
}

function getActiveTabUrl(){
  return new Promise((resolve)=>{
    try{
      chrome.tabs.query({active:true,currentWindow:true}, (tabs)=>{
        if(!tabs || tabs.length===0){resolve('');return}
        resolve(tabs[0].url || '');
      });
    }catch(e){resolve('');}
  });
}

function clamp(n,min,max){return Math.max(min,Math.min(max,n))}

function analyzeURL(url){
  const reasons = [];
  if(!url) return {score:0,reasons};

  try{
    const u = new URL(url);
    const hostname = u.hostname;
    const pathname = u.pathname || '/';
    const protocol = u.protocol.replace(':','');

    // checks
    // 1. IP address instead of domain
    const ipV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const ipV6 = /^\[?[0-9a-fA-F:]+\]?$/;
    if(ipV4.test(hostname) || ipV6.test(hostname)){
      reasons.push({label:'IP address used instead of a domain', weight:30});
    }

    // 2. HTTP instead of HTTPS
    if(protocol === 'http'){
      reasons.push({label:'Not using HTTPS (no secure padlock)', weight:20});
    }

    // 3. Unusually long URL
    const urlLen = url.length;
    if(urlLen > 100) reasons.push({label:'Unusually long URL', weight:12});
    else if(urlLen > 80) reasons.push({label:'Long URL length', weight:6});

    // 4. Excessive subdomains
    const parts = hostname.split('.').filter(Boolean);
    if(parts.length >= 4) reasons.push({label:'Excessive subdomains (possible trickery)', weight:10});

    // 5. Suspicious keywords
    const suspiciousKeywords = ['login','signin','verify','update','secure','account','bank','confirm','password','ssn','social','security','invoice','payment','urgent','verify','confirm','webscr','ebayisapi','paypal','appleid'];
    const hostLower = hostname.toLowerCase();
    for(const kw of suspiciousKeywords){
      if(hostLower.includes(kw)){
        reasons.push({label:`Suspicious keyword in domain: "${kw}"`, weight:8});
        break;
      }
    }
    const pathLower = pathname.toLowerCase();
    for(const kw of ['login','verify','confirm','update','secure','password','banking','otp']){
      if(pathLower.includes(kw)){
        reasons.push({label:`Suspicious keyword in path: "${kw}"`, weight:6});
        break;
      }
    }

    // 6. Hyphen abuse
    const hyphenCount = (hostname.match(/-/g)||[]).length;
    if(hyphenCount >= 3) reasons.push({label:'Multiple hyphens in domain (could be deceptive)', weight:6});

    // 7. URL shortener domains
    const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','bitly.com','ow.ly','is.gd','buff.ly','adf.ly'];
    if(shorteners.includes(hostLower)) reasons.push({label:'URL shortener domain — original target is hidden', weight:14});

    // 8. @ symbol or unusual patterns
    if(url.includes('@')) reasons.push({label:'"@" in URL — may hide the true destination', weight:10});
    if(url.match(/\/\/[\w.-]*\//g)?.length > 2){} // ignore

    // 9. Many path segments
    const segments = pathname.split('/').filter(Boolean);
    if(segments.length >= 6) reasons.push({label:'Many path segments (deep, possibly auto-generated)', weight:6});

    // 10. IP in path or query
    if(url.match(/https?:\/\/(?:\d+\.){3}\d+/)) reasons.push({label:'IP address present in URL', weight:10});

    // 11. Multiple query parameters with odd keys
    const query = u.search;
    if(query && query.length > 80) reasons.push({label:'Long query string (possible tracking or obfuscation)', weight:6});

    // 12. Look for homoglyph-like long host parts (repetition)
    if(hostname.length > 30) reasons.push({label:'Very long domain name (potentially deceptive)', weight:8});

    // 13. Mixed unicode characters (punycode)
    if(hostname.includes('xn--')) reasons.push({label:'Punycode/IDN domain (may hide lookalikes)', weight:12});

    // baseline scoring: start at 0 and add weights
    let score = 0;
    for(const r of reasons) score += r.weight;

    // Heuristic modifiers
    // If domain is well-known safe TLDs (like .gov, .edu) reduce risk
    const safeTlds = ['gov','edu'];
    const tld = parts.length ? parts[parts.length-1].toLowerCase() : '';
    if(safeTlds.includes(tld)) score = Math.max(0, score - 20);

    // If hostname appears short & simple, reduce small amount
    if(hostname.length < 12 && parts.length <= 2 && !hostname.includes('-')) score = Math.max(0, score - 6);

    // Cap to 0..100
    score = clamp(Math.round(score),0,100);

    // Prepare descriptive reasons (dedupe similar)
    const dedup = [];
    const labels = new Set();
    for(const r of reasons){ if(!labels.has(r.label)){ dedup.push(r); labels.add(r.label);} }

    return {
      score,
      reasons: dedup.map(r=>r.label),
      rawReasons: dedup,
      hostname,
      protocol,
      path: pathname
    };

  }catch(err){
    return {score:0,reasons:['Unable to parse URL']};
  }
}

function riskLevel(score){
  if(score < 30) return {level:'Low Risk', color:'#36d399', desc:'Looks safe based on local checks.'};
  if(score < 60) return {level:'Suspicious', color:'#ffb020', desc:'Proceed with caution. Several warning signs detected.'};
  return {level:'High Risk', color:'#ff6b6b', desc:'Many suspicious signals. Avoid entering sensitive data.'};
}

function updateUI(result){
  resultCard.classList.remove('hidden');
  gaugeLabel.textContent = String(result.score);
  gaugeFill.style.width = `${clamp(result.score,0,100)}%`;
  const rl = riskLevel(result.score);
  riskLevelEl.textContent = rl.level;
  riskLevelEl.style.color = rl.color;
  riskDescEl.textContent = rl.desc;

  // reasons
  reasonsList.innerHTML = '';
  if(result.reasons && result.reasons.length){
    for(const r of result.reasons){
      const li = document.createElement('li');
      li.textContent = r;
      reasonsList.appendChild(li);
    }
  }else{
    const li = document.createElement('li'); li.textContent = 'No obvious issues detected by local checks.'; reasonsList.appendChild(li);
  }
}

async function analyzeCurrent(){
  setStatus('Scanning...');
  const url = currentUrl;
  const res = analyzeURL(url);
  updateUI(res);
  setStatus('Ready');
}

async function init(){
  setStatus('Loading...');
  const url = await getActiveTabUrl();
  showUrl(url);
  setStatus('Ready');
}

// highlight on page by injecting content.js and sending a message
function highlightOnPage(){
  if(!currentUrl) return;
  chrome.tabs.query({active:true,currentWindow:true}, (tabs)=>{
    if(!tabs || !tabs[0]) return;
    const tabId = tabs[0].id;
    // inject the content script then send message
    chrome.scripting.executeScript({
      target:{tabId},
      files:['content.js']
    }, ()=>{
      chrome.tabs.sendMessage(tabId, {action:'highlight', url:currentUrl}, ()=>{});
    });
  });
}

// open site in new tab
function openSite(){
  if(!currentUrl) return;
  chrome.tabs.create({url:currentUrl});
}

// event listeners
analyzeBtn.addEventListener('click', analyzeCurrent);
scanAgainBtn.addEventListener('click', analyzeCurrent);
highlightBtn.addEventListener('click', ()=>{ highlightOnPage(); setStatus('Highlight sent'); });
openSiteBtn.addEventListener('click', openSite);

// init
init();
