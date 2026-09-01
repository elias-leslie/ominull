package server

import "encoding/json"

// setupWizardDocument keeps first-run setup as an actual staged workflow. The
// old page placed every setting and diagnostic in one unscrollable document;
// this page makes network, security, installation, and proof separate tasks.
func setupWizardDocument(csrf string, complete bool) ([]byte, string) {
	nonce := newCSPNonce()
	state, _ := json.Marshal(map[string]interface{}{"csrf": csrf, "complete": complete})
	document := `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ominull setup wizard</title><link rel="stylesheet" href="/app.css"></head>
<body class="setup-page">
<main class="setup-shell">
  <header class="setup-head"><div><h1>Ominull setup wizard</h1><p class="sub">Package-owned setup for LAN, direct WAN, or optional free-tier Cloudflare.</p></div><a class="btn" href="/status">Status</a></header>
  <nav class="setup-progress" aria-label="Setup progress">
    <button type="button" data-nav="0" aria-current="step"><b>01</b>Preflight</button>
    <button type="button" data-nav="1"><b>02</b>Network</button>
    <button type="button" data-nav="2"><b>03</b>Security</button>
    <button type="button" data-nav="3"><b>04</b>Install agent</button>
    <button type="button" data-nav="4"><b>05</b>Verify</button>
  </nav>
  <form id="setup-form">
    <section class="setup-step" data-step="0">
      <h2>Host preflight</h2><p>Live checks. Network and heartbeat failures are expected until settings are saved and the first agent checks in.</p>
      <div id="checks-preflight"><p class="empty">Running diagnostics…</p></div>
      <div class="setup-actions"><span></span><div><button class="btn" id="rerun-preflight" type="button">Run again</button><button class="btn btn-primary" data-next="1" type="button">Configure network</button></div></div>
    </section>
    <section class="setup-step" data-step="1" hidden>
      <h2>Administrator and network</h2><p>Console address serves people. Agent address serves bootstrap, packages, enrollment, telemetry, and control.</p>
      <div class="setup-fields">
        <label>Administrator email<input name="email" type="email" autocomplete="email" required placeholder="operator@example.invalid"></label>
        <label>Network mode<select name="network"><option value="lan">LAN / private network</option><option value="direct">Direct WAN with public TLS</option><option value="cloudflare">Cloudflare Tunnel + Access (optional)</option></select></label>
        <label class="field-wide">Console URL<input name="console_url" type="url" required placeholder="http://hub.lan:9999"></label>
        <label class="field-wide">HTTPS agent URL<input name="agent_url" type="url" required placeholder="https://hub.lan:9443"></label>
      </div>
      <p class="pending">LAN console may use HTTP; agent traffic always uses HTTPS. WAN modes use separate HTTPS console and agent hostnames. Keep interactive sign-in off agent hostname.</p>
      <div class="setup-actions"><button class="btn" data-back="0" type="button">Back</button><div><button class="btn btn-primary" data-next="2" type="button">Security settings</button></div></div>
    </section>
    <section class="setup-step" data-step="2" hidden>
      <h2>Certificates and sign-in</h2><p>Self-issued TLS is simplest on LAN. Direct WAN can use an operator-managed ACME certificate. OIDC and Cloudflare stay optional.</p>
      <div class="setup-fields">
        <label>TLS mode<select name="tls_mode"><option value="self-issued">Self-issued Ominull CA (LAN)</option><option value="acme">Operator-managed ACME certificate</option><option value="custom">Other operator certificate</option></select></label>
        <label>Client certificate proof<select name="client_certs"><option value="optional">Verify when presented (migration)</option><option value="required">Require on every agent</option><option value="off">Off (recovery only)</option></select></label>
        <label class="field-wide">Additional certificate names<input name="tls_hosts" placeholder="hub.lan,agent.example.invalid"></label>
        <div class="setup-group setup-fields" id="certificate-files">
          <label>Server certificate path<input name="tls_cert_file" placeholder="/etc/ominull/server.crt"></label>
          <label>Server key path<input name="tls_key_file" placeholder="/etc/ominull/server.key"></label>
        </div>
        <div class="setup-group setup-fields">
          <div class="field-wide"><h3>Optional native OIDC</h3><p class="why">Leave blank to use local admin recovery or Cloudflare Access.</p></div>
          <label class="field-wide">HTTPS issuer<input name="oidc_issuer" type="url" placeholder="https://issuer.example.invalid"></label>
          <label>Client ID<input name="oidc_client_id"></label>
          <label>Redirect URL<input name="oidc_redirect_url" type="url" placeholder="https://console.example.invalid/oidc/callback"></label>
          <label class="field-wide">Client secret<input name="oidc_client_secret" type="password" autocomplete="new-password" placeholder="Stored in a root-only file"></label>
        </div>
        <div class="setup-group setup-fields" id="cloudflare-fields">
          <div class="field-wide"><h3>Cloudflare Access console</h3><p class="why">Free-tier Tunnel and Access are sufficient. Agent hostname has no interactive Access policy.</p></div>
          <label>Access team<input name="access_team" placeholder="team-name"></label>
          <label>Application audience<input name="access_audience" placeholder="audience tag"></label>
        </div>
      </div>
      <p id="save-message" class="setup-message" role="status"></p>
      <div class="setup-actions"><button class="btn" data-back="1" type="button">Back</button><div><button class="btn btn-primary" type="submit">Save and continue</button></div></div>
    </section>
    <section class="setup-step" data-step="3" hidden>
      <h2>Install the first agent</h2><p>Generate Windows or Linux options here. Script verifies signed native package, enrolls computer, and starts one package-owned service.</p>
      <div class="setup-fields">
        <label>Operating system<select id="setup-platform"><option value="linux">Linux</option><option value="windows">Windows</option></select></label>
        <label>Role<select id="setup-role"><option value="workstation">Workstation</option><option value="server">Server</option><option value="kiosk">Kiosk</option><option value="appliance">Appliance</option></select></label>
      </div>
      <div class="setup-actions"><button class="btn" data-back="2" type="button">Back</button><div><button id="setup-generate" class="btn btn-primary" type="button">Generate install options</button><button class="btn" data-next="4" type="button">Verify agent</button></div></div>
      <div id="setup-installer" class="setup-message" aria-live="polite"></div>
    </section>
    <section class="setup-step" data-step="4" hidden>
      <h2>Verify and finish</h2><p>Finish after a current heartbeat proves native package provenance, unique device credentials, and client-certificate transport.</p>
      <div class="setup-actions"><button class="btn" data-back="3" type="button">Back</button><div><button id="rerun-final" class="btn" type="button">Run checks again</button><button id="complete" class="btn btn-primary" type="button" disabled>Complete setup</button></div></div>
      <div id="checks-final"><p class="empty">Running diagnostics…</p></div>
      <p id="complete-message" class="setup-message" role="status"></p>
    </section>
  </form>
</main>
<script nonce="` + nonce + `">
(function(){
  "use strict";
  var SETUP=` + string(state) + `,current=0,hydrated=false;
  var q=function(s){return document.querySelector(s);},qa=function(s){return Array.prototype.slice.call(document.querySelectorAll(s));},field=function(n){return q('[name="'+n+'"]');};
  function node(tag,cls,text){var out=document.createElement(tag);if(cls)out.className=cls;if(text!==undefined)out.textContent=text;return out;}
  function message(target,text,tone){target.textContent=text||"";target.dataset.tone=tone||"";}
  function show(step){current=step;qa("[data-step]").forEach(function(s){s.hidden=Number(s.dataset.step)!==step;});qa("[data-nav]").forEach(function(b){if(Number(b.dataset.nav)===step)b.setAttribute("aria-current","step");else b.removeAttribute("aria-current");});window.scrollTo(0,0);}
  function validStep(step){var bad=qa('[data-step="'+step+'"] input[required],[data-step="'+step+'"] select[required]').filter(function(input){return !input.checkValidity();})[0];if(bad){bad.reportValidity();bad.focus();return false;}return true;}
  qa("[data-nav]").forEach(function(b){b.addEventListener("click",function(){show(Number(b.dataset.nav));});});qa("[data-next]").forEach(function(b){b.addEventListener("click",function(){if(validStep(current))show(Number(b.dataset.next));});});qa("[data-back]").forEach(function(b){b.addEventListener("click",function(){show(Number(b.dataset.back));});});
  async function api(url,options){options=options||{};options.headers=Object.assign({"Content-Type":"application/json","X-CSRF-Token":SETUP.csrf},options.headers||{});var response=await fetch(url,options),body=await response.json().catch(function(){return {};});if(!response.ok)throw new Error(body.error||"request failed");return body;}
  function renderChecks(box,body){box.textContent="";var results=body.results||[],counts={pass:0,fail:0,warn:0,not_configured:0};results.forEach(function(item){counts[item.state]=(counts[item.state]||0)+1;});var summary=node("div","diag-summary");[["pass","Pass"],["fail","Fail"],["warn","Warning"],["not_configured","Not configured"]].forEach(function(pair){summary.appendChild(node("span","st",String(counts[pair[0]])+" "+pair[1]));});var grid=node("div","diag-grid");results.forEach(function(item){var card=node("article","diag");card.dataset.state=item.state||"not_configured";card.appendChild(node("span","diag-mark",item.state==="pass"?"✓":item.state==="fail"?"×":item.state==="warn"?"!":"–"));var copy=node("div");copy.appendChild(node("h3","",item.title||"Check"));copy.appendChild(node("p","",item.summary||"No result"));if(item.remediation)copy.appendChild(node("p","remediation",item.remediation));card.appendChild(copy);grid.appendChild(card);});box.append(summary,grid);}
  function hydrate(c){if(hydrated)return;hydrated=true;[["network","network_mode"],["console_url","console_url"],["agent_url","agent_url"],["tls_mode","tls_mode"],["client_certs","client_certs"],["tls_cert_file","tls_cert_file"],["tls_key_file","tls_key_file"],["tls_hosts","tls_hosts"],["oidc_issuer","oidc_issuer"],["oidc_client_id","oidc_client_id"],["oidc_redirect_url","oidc_redirect_url"],["access_team","access_team"],["access_audience","access_audience"]].forEach(function(pair){var input=field(pair[0]),value=c[pair[1]];if(input&&value!==undefined&&value!==null)input.value=Array.isArray(value)?value.join(","):value;});syncConditional();}
  function load(){return api("/api/v1/setup/status").then(function(body){renderChecks(q("#checks-preflight"),body);renderChecks(q("#checks-final"),body);q("#complete").disabled=!!body.has_failures;hydrate(body.configuration||{});return body;}).catch(function(error){q("#checks-preflight").textContent=error.message;q("#checks-final").textContent=error.message;});}
  function syncConditional(){q("#cloudflare-fields").hidden=field("network").value!=="cloudflare";q("#certificate-files").hidden=field("tls_mode").value==="self-issued";}
  field("network").addEventListener("change",syncConditional);field("tls_mode").addEventListener("change",syncConditional);
  q("#setup-form").addEventListener("submit",async function(event){event.preventDefault();if(!event.target.reportValidity())return;var form=new FormData(event.target),save=q("#save-message");message(save,"Saving validated configuration…","");try{var body={configuration:{network_mode:form.get("network"),console_url:form.get("console_url"),agent_url:form.get("agent_url"),tls_mode:form.get("tls_mode"),client_certs:form.get("client_certs"),tls_cert_file:form.get("tls_cert_file"),tls_key_file:form.get("tls_key_file"),tls_hosts:String(form.get("tls_hosts")||"").split(",").map(function(v){return v.trim();}).filter(Boolean),oidc_issuer:form.get("oidc_issuer"),oidc_client_id:form.get("oidc_client_id"),oidc_redirect_url:form.get("oidc_redirect_url"),access_team:form.get("access_team"),access_audience:form.get("access_audience"),cloudflare:form.get("network")==="cloudflare"},local_admin_email:form.get("email"),oidc_client_secret:form.get("oidc_client_secret")};var result=await api("/api/v1/setup/apply",{method:"POST",body:JSON.stringify(body)});message(save,result.restart_required?"Saved. Restart ominull-hub.service, create a fresh setup token, then return here to install and verify.":"Configuration saved.",result.restart_required?"warn":"ok");if(!result.restart_required){await load();show(3);}}catch(error){message(save,error.message,"crit");}});
  function download(filename,text){var url=URL.createObjectURL(new Blob([text],{type:"text/plain"})),link=node("a");link.href=url;link.download=filename;document.body.appendChild(link);link.click();link.remove();setTimeout(function(){URL.revokeObjectURL(url);},1000);}
  q("#setup-generate").addEventListener("click",async function(){var button=this,box=q("#setup-installer"),platform=q("#setup-platform").value;button.disabled=true;button.textContent="Generating…";message(box,"Generating secure "+(platform==="windows"?"Windows":"Linux")+" options…","");try{var result=await api("/api/v1/enrolment/script",{method:"POST",body:JSON.stringify({platform:platform,kind:"invitation",role:q("#setup-role").value,one_liner:true})});box.textContent="";box.dataset.tone="";var wrap=node("div","installer-result");wrap.appendChild(node("h3","",(platform==="windows"?"Windows":"Linux")+" installer ready · "+(result.expires_in||"30 minutes")));var downloadButton=node("button","btn btn-primary","Download "+result.filename);downloadButton.type="button";downloadButton.addEventListener("click",function(){download(result.filename,result.script||"");});wrap.appendChild(downloadButton);if(result.one_liner){wrap.appendChild(node("p","why","Or run generic command, then enter separate code when prompted."));wrap.appendChild(node("pre","cmd",result.one_liner));wrap.appendChild(node("pre","cmd",result.enrollment_code||""));}box.appendChild(wrap);}catch(error){message(box,error.message,"crit");}finally{button.disabled=false;button.textContent="Generate install options";}});
  q("#rerun-preflight").addEventListener("click",load);q("#rerun-final").addEventListener("click",load);q("#complete").addEventListener("click",async function(){var target=q("#complete-message");message(target,"Running final proof…","");try{await api("/api/v1/setup/complete",{method:"POST",body:"{}"});message(target,"Setup complete. Opening console…","ok");setTimeout(function(){location.href="/";},600);}catch(error){message(target,error.message,"crit");await load();}});
  syncConditional();show(SETUP.complete?4:0);load();
})();
</script>
</body></html>`
	return []byte(document), nonce
}
