// content.js - runs in page context when injected. Highlights suspicious links based on a simple heuristic.
// Note: injected only when user requests 'Highlight'. All analysis remains local and transient.

(function(){
  // avoid running automatically
  chrome.runtime.onMessage.addListener((msg, sender, sendResp)=>{
    if(!msg || msg.action !== 'highlight') return;
    try{
      const suspicious = [];
      const links = Array.from(document.querySelectorAll('a[href]'));
      const keywords = ['login','signin','verify','confirm','update','secure','bank','password','account'];
      for(const a of links){
        const href = a.getAttribute('href') || '';
        const txt = (a.textContent||'').toLowerCase();
        const hrl = href.toLowerCase();
        let score = 0;
        if(hrl.includes('@')) score += 2;
        if(hrl.length > 200) score += 2;
        for(const kw of keywords){ if(hrl.includes(kw) || txt.includes(kw)) score += 2; }
        if(hrl.includes('http://')) score += 2;
        if(score >= 3){
          suspicious.push(a);
        }
      }
      // highlight elements
      suspicious.forEach(el=>{
        el.style.outline = '3px dashed rgba(255,107,107,0.9)';
        el.style.background = 'linear-gradient(90deg, rgba(255,107,107,0.06), rgba(255,255,255,0.02))';
        el.scrollIntoView({behavior:'smooth', block:'center'});
      });
      // send back count
      sendResp({count: suspicious.length});
    }catch(e){sendResp({error:true})}
  });
})();
