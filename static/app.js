/* STEGOSCOPE browser UI — self-hosted, no frontend dependencies or remote requests. */
(() => {
  'use strict';
  let current = null;
  let toolStatuses = [];
  let active = 'overview';
  let toastTimer;
  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmt = (n) => new Intl.NumberFormat('en-US').format(n || 0);
  const size = n => (n >= 1048576 ? (n / 1048576).toFixed(2) + ' MiB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KiB' : n + ' B');
  const u = path => path;
  const fileUrl = (type, id = current?.id) => `/api/${type}/${encodeURIComponent(id)}`;
  function toast(message) { const node = $('toast'); node.textContent = message; node.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => node.classList.remove('show'), 4300); }
  function setLoading(value) { $('loadingState').hidden = !value; $('demoBtn').disabled = value; $('browseBtn').disabled = value; }
  async function request(path, options = {}) {
    const response = await fetch(path, options);
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try { const json = await response.json(); message = typeof json.detail === 'string' ? json.detail : message; } catch (_) { /* non-JSON error */ }
      throw new Error(message);
    }
    return response.json();
  }
  function setView(next) {
    if (!current) { toast('Upload evidence or load the demo case first.'); return; }
    active = next;
    document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === next));
    document.querySelectorAll('.view').forEach(el => el.classList.toggle('active', el.dataset.panel === next));
    document.querySelectorAll('.view').forEach(el => el.hidden = el.dataset.panel !== next);
    $('breadcrumb').textContent = next.toUpperCase();
    if (next === 'overview') requestAnimationFrame(drawEntropy);
    window.scrollTo({top: 0, behavior: 'smooth'});
  }
  async function loadFile(file) {
    if (!file) return;
    if (file.size > 32 * 1024 * 1024) { toast('Maximum size is 32 MiB.'); return; }
    setLoading(true);
    try {
      const form = new FormData(); form.append('file', file, file.name);
      const data = await request('/api/analyze', {method: 'POST', body: form});
      showCase(data);
      toast('Evidence analyzed locally. Explore each laboratory.');
    } catch (err) { toast(`Analysis failed: ${err.message}`); }
    finally { setLoading(false); }
  }
  async function loadDemo() {
    setLoading(true);
    try { showCase(await request('/api/demo', {method: 'POST'})); toast('Synthetic LSB challenge loaded — inspect the flags and image channels.'); }
    catch (err) { toast(err.message); }
    finally { setLoading(false); }
  }
  function showCase(data) {
    current = data;
    $('workspace').hidden = false; $('welcome').hidden = true;
    $('sideCase').textContent = 'ACTIVE / LOCAL'; $('sideFilename').textContent = data.filename;
    $('fileName').textContent = data.filename;
    $('caseId').textContent = `CASE / ${data.id.slice(0, 8).toUpperCase()}`;
    $('shortHash').textContent = `SHA-256 · ${data.sha256}`;
    $('metricKind').textContent = data.kind; $('metricSize').textContent = size(data.bytes);
    $('metricEntropy').textContent = `${data.entropy.toFixed(2)} / 8`;
    $('metricFlags').textContent = String(data.flags.length).padStart(2, '0');
    renderOverview(); renderImage(); renderAudio(); renderExtract(); renderTools(); renderReport(); setView('overview');
  }
  function renderOverview() {
    const d = current;
    $('sigCount').textContent = `${d.signatures.length} MATCHES`;
    $('signatureRows').innerHTML = d.signatures.length ? d.signatures.map(s => `<tr><td class="mono">${esc(s.hex)}</td><td>${esc(s.type)}</td><td><span class="pill ${s.embedded ? '' : 'neutral'}">${s.embedded ? 'NON-ZERO' : 'HEADER'}</span></td></tr>`).join('') : '<tr><td colspan="3" class="empty-row">No recognizable signatures found</td></tr>';
    $('flagsRows').innerHTML = d.flags.length ? d.flags.map(flag => `<div class="flag-entry"><span>◈</span><code>${esc(flag)}</code></div>`).join('') : '<div class="flag-placeholder">No flag-shaped strings found in the raw evidence or built-in LSB previews. This does not rule out hidden data.</div>';
    $('guidanceRows').innerHTML = d.guidance.map((r, idx) => `<div class="guidance-item"><div class="guidance-n">${String(idx + 1).padStart(2,'0')}</div><div><b>${esc(r.title)}</b><p>${esc(r.detail)}</p></div></div>`).join('');
    $('hexRows').innerHTML = d.hex.map(r => `<div class="hex-row"><span class="hex-addr">${r.offset}</span><span class="hex-bytes">${r.hex.padEnd(48, ' ')}</span><span class="hex-ascii">${esc(r.ascii)}</span></div>`).join('');
    $('decodedRows').innerHTML = d.decoded.length ? `<div class="decoded-title">POSSIBLE ENCODED TEXT (${d.decoded.length})</div>` + d.decoded.map(x => `<div class="decoded-entry">${esc(x.method)} @${esc(x.offset)} → ${esc(x.decoded)}</div>`).join('') : '';
    if (d.text_stego) { $('decodedRows').innerHTML += `<div class="decoded-title">INVISIBLE TEXT MARKERS</div><div class="decoded-entry">Zero-width: ${d.text_stego.zero_width_count} · Lines with trailing whitespace: ${d.text_stego.trailing_whitespace_lines}${d.text_stego.zero_width_decoded ? '<div>' + esc(d.text_stego.zero_width_decoded) + '</div>' : ''}</div>`; }
    filterStrings();
  }
  function filterStrings() {
    if (!current) return;
    const q = $('stringSearch').value.trim().toLowerCase();
    const matches = current.strings.filter(row => row.text.toLowerCase().includes(q)).slice(0, 90);
    $('stringsRows').innerHTML = matches.length ? matches.map(x => `<div class="string-entry"><span class="offset">0x${x.offset.toString(16).toUpperCase()}</span><code>${esc(x.text)}</code></div>`).join('') : '<div class="flag-placeholder">No matching printable strings.</div>';
  }
  function drawEntropy() {
    if (!current) return;
    const canvas = $('entropyCanvas'), context = canvas.getContext('2d');
    const cssWidth = canvas.clientWidth; if (!cssWidth) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = Math.max(200, cssWidth), h = 210;
    canvas.width = Math.floor(w * dpr); canvas.height = Math.floor(h * dpr);
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    context.clearRect(0,0,w,h);
    const left = 32, right = 8, top = 10, bottom = 25, iw = w - left - right, ih = h - top - bottom;
    context.strokeStyle = '#22384b'; context.lineWidth = 1;
    context.font = '10px monospace'; context.fillStyle = '#657d95';
    for (let i = 0; i <= 4; i++) { const y = top + ih - ih * i / 4; context.beginPath(); context.moveTo(left,y); context.lineTo(w-right,y); context.stroke(); context.fillText(String(i*2),4,y+4); }
    const values = current.entropy_profile;
    if (!values.length) return;
    const xAt = i => left + (values.length === 1 ? 0 : i / (values.length - 1) * iw);
    const yAt = v => top + ih - v / 8 * ih;
    const gradient = context.createLinearGradient(0, top, 0, top + ih);
    gradient.addColorStop(0, '#58e9be4d'); gradient.addColorStop(1, '#58e9be00');
    context.beginPath(); context.moveTo(left,top+ih);
    values.forEach((v,i) => context.lineTo(xAt(i),yAt(v.entropy)));
    context.lineTo(xAt(values.length-1),top+ih);context.closePath();context.fillStyle=gradient;context.fill();
    context.beginPath();values.forEach((v,i) => i ? context.lineTo(xAt(i),yAt(v.entropy)) : context.moveTo(xAt(i),yAt(v.entropy)));
    context.strokeStyle='#62e6c5';context.lineWidth=2;context.stroke();
  }
  function renderImage() {
    const d = current, ok = d.image && !d.image.error;
    $('imageEmpty').hidden = !!ok; $('imageContent').hidden = !ok;
    if (!ok) return;
    $('imageDimensions').textContent = `${fmt(d.image.width)} × ${fmt(d.image.height)}`;
    $('previewImage').src = fileUrl('image', d.id) + '/preview';
    $('imageMeta').innerHTML = [['FORMAT',d.image.format],['MODE',d.image.mode],['FRAMES',d.image.frames],['R LSB ONES',d.image.lsb_one_ratio?.R],['G LSB ONES',d.image.lsb_one_ratio?.G],['B LSB ONES',d.image.lsb_one_ratio?.B]].map(([k,v]) => `<span>${esc(k)} · ${esc(v ?? 'N/A')}</span>`).join('');
    updatePlane();
    $('lsbRows').innerHTML = d.lsb?.length ? d.lsb.map(x => `<tr><td class="mono">${esc(x.channels)}</td><td>${esc(x.order)}</td><td>${Math.round(x.printable_ratio*100)}%</td><td>${esc((x.flags || []).join(' ') || x.text || x.magic || '—')}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-row">Only lossless PNG and BMP are scanned by the built-in LSB triage</td></tr>';
    const rows = d.png?.chunks || []; $('chunkCount').textContent = rows.length + ' CHUNKS';
    $('pngRows').innerHTML = rows.length ? rows.map(x => `<tr><td class="mono">${esc(x.type)}</td><td class="mono">0x${x.offset.toString(16).toUpperCase()}</td><td>${fmt(x.size)} B</td><td><span class="pill ${x.crc === 'valid' ? '' : 'neutral'}">${esc(x.crc)}</span></td></tr>`).join('') : '<tr><td colspan="4" class="empty-row">PNG chunks available for PNG evidence only</td></tr>';
  }
  function updatePlane() { if (current?.image && !current.image.error) { $('planeImage').src = `/api/image/${current.id}/plane?channel=${encodeURIComponent($('planeChannel').value)}&bit=${encodeURIComponent($('planeBit').value)}`; } }
  function renderAudio() {
    const d = current, ok = d.audio && !d.audio.error;
    $('audioEmpty').hidden = !!ok; $('audioContent').hidden = !ok;
    if (!ok) return;
    $('audioRate').textContent = fmt(d.audio.sample_rate) + ' Hz';
    $('audioDuration').textContent = d.audio.duration_seconds + ' s';
    $('audioChannels').textContent = String(d.audio.channels);
    $('audioWidth').textContent = (d.audio.sample_width * 8) + ' bit';
    $('spectrumImage').src = fileUrl('audio', d.id) + '/spectrogram';
    const x = d.audio_lsb;
    $('audioClues').textContent = x ? ((x.flags.length ? 'FLAG CANDIDATES\n' + x.flags.join('\n') + '\n\n' : '') + 'PCM LSB STRING CLUES\n' + (x.strings.map(s => `${s.offset}: ${s.text}`).join('\n') || '(no printable strings found)')) : 'PCM LSB analysis unavailable for this WAV encoding.';
  }
  function renderExtract() {
    const d = current;
    $('carveOffset').value = d.trailing_offset ?? ((d.signatures.find(s => s.offset > 0) || {}).offset ?? 0);
    $('carveLength').value = '0';
    $('trailerHint').textContent = d.trailing_bytes ? `Detected ${fmt(d.trailing_bytes)} trailing bytes at offset ${fmt(d.trailing_offset)}.` : 'No trailing image bytes detected. Use signature offsets to carve manually.';
    $('extractLog').textContent = 'No extraction jobs started for this evidence.';
    $('artifactList').innerHTML = '';
  }
  function renderTools() {
    const specs = {
      exiftool:['◇','Read EXIF tags, file metadata and embedded descriptors.'],
      binwalk:['▧','Identify embedded signatures and archive boundaries. Scan only.'],
      zsteg:['▤','Detect common PNG/BMP bit-layout steganography.'],
      steghide_info:['◈','Probe supported files for Steghide metadata.'],
      steghide_extract:['⇣','Password-protected extraction is in Payload Extraction.'],
      stegseek:['⌕','Wordlist recovery is in Payload Extraction.'],
      ffprobe:['≋','Inspect technical stream/container metadata.'],
      zbarimg:['▦','Read QR codes and barcodes visible in images.'],
      tesseract:['T','Recognize visible text and letters from image files.'],
    };
    $('toolsGrid').innerHTML = toolStatuses.map(t => {
      const [icon,desc] = specs[t.id] || ['⌘','External analysis adapter'];
      const manual = ['steghide_extract','stegseek'].includes(t.id);
      return `<div class="tool-card"><div class="tool-card-top"><div class="tool-icon">${icon}</div><div class="status ${t.installed ? 'ok' : ''}">${t.installed ? '● INSTALLED' : '○ MISSING'}</div></div><b>${esc(t.binary)}</b><p>${esc(desc)}</p><button class="btn btn-outline" data-run="${esc(t.id)}" ${!t.installed || manual ? 'disabled' : ''}>${manual ? 'Use extraction tab' : t.installed ? 'Run analysis ↗' : 'Not installed'}</button></div>`;
    }).join('');
  }
  function renderReport() {
    const d = current;
    $('reportSummary').innerHTML = [['EVIDENCE',d.filename],['IDENTIFIED TYPE',d.kind],['RAW SIZE',size(d.bytes)],['SHA-256',d.sha256],['SHANNON ENTROPY',d.entropy.toFixed(4)],['FLAG-SHAPED HITS',d.flags.length],['SIGNATURE HITS',d.signatures.length],['TRAILING DATA',size(d.trailing_bytes)]].map(([label,value]) => `<div class="report-info"><small>${esc(label)}</small><b>${esc(value)}</b></div>`).join('');
  }
  async function executeTool(tool, target='toolLog') {
    if (!current) return;
    if (['steghide_extract','stegseek'].includes(tool) && !toolStatuses.some(t => t.id === tool && t.installed)) { toast(`Install ${tool === 'stegseek' ? 'stegseek' : 'steghide'} to use this adapter.`); return; }
    const log = $(target); log.textContent = `> ${tool}\nRunning locally against current evidence…`;
    const body = {tool};
    if (tool === 'steghide_extract') body.passphrase = $('stegPassword').value;
    if (tool === 'stegseek') body.wordlist = $('wordlist').value;
    const button = document.querySelector(`[data-run="${tool}"]`);
    if (button) button.disabled = true;
    try {
      const result = await request(`/api/tools/${current.id}/run`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
      log.textContent = `$ ${tool}\nexit: ${result.exit_code ?? 'N/A'} | ${result.duration_seconds}s${result.timed_out ? ' | TIMED OUT' : ''}\n\n${result.output || '(no output)'}`;
      if (result.artifact) {
        const holder = $(target === 'toolLog' ? 'toolArtifact' : 'artifactList');
        const link = document.createElement('a');link.className='artifact-link';link.href=result.artifact.url;link.textContent=`⇩ Download recovered ${result.artifact.name} (${size(result.artifact.bytes)})`;
        holder.replaceChildren(link);
      }
      toast(`${tool} finished${result.exit_code === 0 ? ' successfully' : ''}. Review console output.`);
    } catch (err) { log.textContent = `${tool}: ${err.message}`;toast(err.message); }
    finally { if (button) button.disabled = false; }
  }
  async function runAllReadOnly() {
    if (!current) return;
    const kind = current.kind;
    const supported = toolStatuses.filter(t => t.installed && !['steghide_extract', 'stegseek'].includes(t.id) &&
      (t.id !== 'zsteg' || ['PNG image','BMP image'].includes(kind)) &&
      (t.id !== 'steghide_info' || ['JPEG image','BMP image','WAV audio'].includes(kind)) &&
      (!['zbarimg','tesseract'].includes(t.id) || (current.image && !current.image.error)));
    if (!supported.length) { toast('No compatible external tools are installed. Built-in analysis is already complete.'); return; }
    const btn = $('runAllTools'), log = $('toolLog');btn.disabled = true;
    log.textContent = `Running ${supported.length} read-only adapters locally...`;
    for (const [i,t] of supported.entries()) {
      log.textContent += `

[${i+1}/${supported.length}] ${t.id}...`;
      try {
        const r = await request(`/api/tools/${current.id}/run`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({tool:t.id})});
        log.textContent += `
Exit ${r.exit_code ?? 'N/A'} (${r.duration_seconds}s)
${r.output}`;
      } catch (err) {log.textContent += `
ERROR: ${err.message}`;}
      log.scrollTop = log.scrollHeight;
    }
    btn.disabled = false;toast(`Read-only scan completed across ${supported.length} tools.`);
  }
  function download(path) { if(!current)return; const anchor=document.createElement('a');anchor.href=path;document.body.append(anchor);anchor.click();anchor.remove(); }
  function reportDownload() { if(current) download(`/api/download/${current.id}/report`); }
  function bind() {
    document.querySelectorAll('.nav-item').forEach(el => el.addEventListener('click', () => setView(el.dataset.view)));
    $('browseBtn').addEventListener('click', () => $('fileInput').click());
    $('fileInput').addEventListener('change', ev => { loadFile(ev.target.files[0]); ev.target.value=''; });
    $('dropzone').addEventListener('click', ev => {if(!ev.target.closest('button'))$('fileInput').click();});
    $('dropzone').addEventListener('dragover', ev => {ev.preventDefault();$('dropzone').classList.add('drag-over');});
    $('dropzone').addEventListener('dragleave', ev => {ev.preventDefault();$('dropzone').classList.remove('drag-over');});
    $('dropzone').addEventListener('drop', ev => {ev.preventDefault();$('dropzone').classList.remove('drag-over');loadFile(ev.dataTransfer?.files?.[0]);});
    $('demoBtn').addEventListener('click', loadDemo);
    $('stringSearch').addEventListener('input',filterStrings);
    $('planeChannel').addEventListener('change',updatePlane);$('planeBit').addEventListener('change',updatePlane);
    $('audioDownload').addEventListener('click',() => download(`/api/download/${current.id}/audio-lsb`));
    $('extractLsb').addEventListener('click',() => {if(!current?.image || current.image.error){toast('Load a supported image first.');return;}download(`/api/download/${current.id}/lsb?channels=${encodeURIComponent($('extractChannels').value)}&bits=${$('extractBits').value}&order=${$('extractOrder').value}`);});
    $('carveBtn').addEventListener('click',() => {if(!current)return;let offset=Number($('carveOffset').value),length=Number($('carveLength').value);if(!Number.isSafeInteger(offset)||offset<0||offset>=current.bytes||!Number.isSafeInteger(length)||length<0){toast('Enter a valid byte offset and length.');return;}download(`/api/download/${current.id}/carve?offset=${offset}&length=${length}`);});
    $('stegExtractBtn').addEventListener('click',()=>executeTool('steghide_extract','extractLog'));
    $('stegseekBtn').addEventListener('click',()=>executeTool('stegseek','extractLog'));
    $('runAllTools').addEventListener('click',runAllReadOnly);
    $('toolsGrid').addEventListener('click',ev=>{const btn=ev.target.closest('[data-run]');if(btn&&!btn.disabled)executeTool(btn.dataset.run);});
    $('clearToolOutput').addEventListener('click',()=>{$('toolLog').textContent='Console cleared.';$('toolArtifact').replaceChildren();});
    $('downloadReport').addEventListener('click',reportDownload);$('reportTop').addEventListener('click',reportDownload);
    $('copyHash').addEventListener('click',async()=>{if(!current)return;try{await navigator.clipboard.writeText(current.sha256);toast('SHA-256 copied');}catch(_){toast(current.sha256);}});
    $('copySummary').addEventListener('click',async()=>{if(!current)return;const text=`STEGOSCOPE CTF CASE\nFile: ${current.filename}\nFormat: ${current.kind}\nBytes: ${current.bytes}\nSHA-256: ${current.sha256}\nEntropy: ${current.entropy}\nFlag candidates: ${current.flags.join(', ')||'none'}\nMarkers: ${current.signatures.length}\nHeuristic indicators are not proof of hidden data.`;try{await navigator.clipboard.writeText(text);toast('Summary copied');}catch(_){toast('Copy failed; use the JSON report instead.');}});
    window.addEventListener('resize',()=>{if(active==='overview')drawEntropy();});
  }
  async function init() {
    bind();
    try { const data = await request('/api/health');toolStatuses=data.tools;$('engineLabel').textContent='LOCAL ENGINE ONLINE';$('apiDot').classList.remove('offline'); }
    catch (err) { $('engineLabel').textContent='ENGINE UNAVAILABLE';$('apiDot').classList.add('offline');toast('Local API is not responding. Start the FastAPI server.'); }
  }
  init();
})();
