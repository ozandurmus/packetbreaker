import {useState} from 'react';

export function AnonymizeExport({disabled}:{disabled:boolean}) {
  const [open,setOpen]=useState(false), [busy,setBusy]=useState(false);
  const [mode,setMode]=useState('zero'), [mapping,setMapping]=useState(false), [error,setError]=useState('');
  async function download() {
    setBusy(true);setError('');
    try {
      const response=await fetch(`/api/anonymize?mode=${mode}&map_ips=${mapping}`,{method:'POST',headers:{'X-PacketBreaker':'local'}});
      if(!response.ok)throw new Error((await response.json()).detail||'Anonymization failed');
      const url=URL.createObjectURL(await response.blob());
      const a=document.createElement('a');a.href=url;a.download='anonymized-captures.zip';a.click();
      setTimeout(()=>URL.revokeObjectURL(url),1000);
    } catch(e) {setError(String(e));} finally {setBusy(false);}
  }
  return <div><button className="secondary" disabled={disabled||busy} onClick={()=>setOpen(!open)}>Anonymize captures</button>
    {open&&<section aria-label="Anonymized capture export"><p>Export all ready captures with payload removed and MACs masked. Metadata and TLS secrets are removed. Timing, header options and traffic patterns remain visible. Content-based analysis becomes unknown.</p>
    <label>Payload <select value={mode} onChange={e=>setMode(e.target.value)} disabled={busy}><option value="zero">Zero bytes, keep captured lengths</option><option value="headers-only">Headers only, keep wire lengths</option></select></label>
    <label><input type="checkbox" checked={mapping} onChange={e=>setMapping(e.target.checked)} disabled={busy}/> Map IPs consistently across files (prefix preserving)</label>
    <p className="hint">IPs are kept by default. Mapping uses one private key saved in this project; the key is never included in the ZIP. Original files stay unchanged. Unsupported headers fail the export.</p>
    <button disabled={busy||disabled} onClick={download}>{busy?'Sanitizing captures…':'Download sanitized ZIP'}</button>{error&&<p role="alert">{error}</p>}</section>}
  </div>;
}
