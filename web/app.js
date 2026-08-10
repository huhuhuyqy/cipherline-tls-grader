"use strict";

const state = {
  scans: [],
  jobs: [],
  analysis: null,
  analysisSelection: {compareField: "", groupA: "", groupB: "", strata: []},
  batchFileText: "",
  batchTargets: [],
};
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const safe = (value) => String(value ?? "--").replace(/[&<>'"]/g, character => (
  {"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[character]
));
const number = (value, suffix = "") => (
  value === null || value === undefined ? "--" : `${Number(value).toFixed(Number(value) % 1 ? 1 : 0)}${suffix}`
);
const isScored = scan => scan.status === "completed" && Number.isFinite(Number(scan.scores?.overall));
const date = value => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value || "--";
  return parsed.toLocaleString("en-SG", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
};

async function api(path, options = {}) {
  const config = {...options, headers: {"Content-Type":"application/json", ...(options.headers || {})}};
  const response = await fetch(path, config);
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("json") ? await response.json() : await response.text();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function toast(message, error = false) {
  const item = document.createElement("div");
  item.className = `toast${error ? " error" : ""}`;
  item.textContent = message;
  $("#toast-region").append(item);
  setTimeout(() => item.remove(), 4500);
}

const titles = {
  overview: "Research overview",
  scan: "Scan laboratory",
  results: "Evidence archive",
  analysis: "Statistical analysis",
  method: "Method & controls",
};

function navigate(route) {
  if (!titles[route]) route = "overview";
  $$(".page").forEach(element => element.classList.toggle("active", element.id === `page-${route}`));
  $$(".nav-item").forEach(element => element.classList.toggle("active", element.dataset.route === route));
  $("#page-title").textContent = titles[route];
  history.replaceState(null, "", `#${route}`);
  window.scrollTo({top:0, behavior:"smooth"});
  if (route === "results") refreshScans();
  if (route === "analysis") refreshAnalysis();
  if (route === "scan") refreshJobs();
}

function analysisQuery() {
  const parameters = new URLSearchParams();
  const selection = state.analysisSelection;
  if (selection.compareField) parameters.set("compare_field", selection.compareField);
  if (selection.groupA) parameters.set("group_a", selection.groupA);
  if (selection.groupB) parameters.set("group_b", selection.groupB);
  selection.strata.forEach(stratum => parameters.append("stratum", stratum));
  return parameters.toString();
}

function updateExportLinks() {
  const query = analysisQuery();
  $("#export-csv").href = `/api/export.csv?${query}`;
  $("#export-html").href = `/api/export.html?${query}`;
}

async function refreshHealth() {
  try {
    const [health, capabilities] = await Promise.all([api("/api/health"), api("/api/capabilities")]);
    $("#health-dot").classList.add("ok");
    $("#health-text").textContent = `Local engine v${health.version || "?"} online`;
    const legacy = capabilities.ssl2_ssl3 === "raw_client_hello_probe" ? " / SSL2 and SSL3 active" : " / SSL2 and SSL3 unavailable";
    $("#openssl-status").textContent = `${capabilities.openssl_version || "OpenSSL not found"}${legacy}`;
  } catch (error) {
    $("#health-text").textContent = "Engine unavailable";
    $("#openssl-status").textContent = error.message;
  }
}

async function refreshScans() {
  const data = await api("/api/scans?limit=0");
  state.scans = data.items;
  renderResults();
  renderRecent();
  updateDataLabelControls();
  if (state.analysis) renderOverview();
  return state.scans;
}

async function refreshAnalysis() {
  state.analysis = await api(`/api/analysis?${analysisQuery()}`);
  renderAnalysis();
  renderOverview();
  updateExportLinks();
  return state.analysis;
}

async function refreshAll() {
  try {
    await Promise.all([refreshHealth(), refreshScans(), refreshJobs()]);
    await refreshAnalysis();
  } catch (error) {
    toast(error.message, true);
  }
}

function uniqueCompletedScans() {
  const seenTargets = new Set();
  return state.scans.filter(scan => {
    const key = `${String(scan.hostname || "").toLowerCase()}:${scan.port || 443}`;
    if (scan.status !== "completed" || seenTargets.has(key)) return false;
    seenTargets.add(key);
    return true;
  });
}

function renderOverview() {
  const analysis = state.analysis;
  if (!analysis) return;
  $("#metric-real").textContent = analysis.total_collected ?? analysis.collected;
  $("#overview-empty-guide").classList.toggle("hidden", state.scans.length > 0);
  const valid = uniqueCompletedScans();
  const scores = valid.map(scan => Number(scan.scores?.overall)).filter(Number.isFinite);
  $("#metric-mean").textContent = scores.length ? number(scores.reduce((left, right) => left + right, 0) / scores.length) : "--";
  const tls13 = valid.filter(scan => scan.protocols?.["TLS 1.3"] === "supported").length;
  $("#metric-tls13").textContent = valid.length ? number(tls13 / valid.length * 100, "%") : "--";
  $("#metric-critical").textContent = analysis.finding_counts?.critical || 0;
  const combinations = analysis.combinations || [];
  const maximum = Math.max(1, ...combinations.map(item => item.n));
  $("#strata-progress").innerHTML = combinations.length ? combinations.map(item => (
    `<div class="stratum-line"><b>${safe(item.country)} / ${safe(item.sector)}</b><div class="progress"><i style="width:${item.n / maximum * 100}%"></i></div><small>${item.n}</small></div>`
  )).join("") : analysis.total_collected
    ? '<div class="empty-state">Descriptive analysis is available for the hostname list. Add country and sector columns to create grouped comparisons.</div>'
    : '<div class="empty-state">No observations yet.</div>';
}

function renderRecent() {
  const recent = state.scans.slice(0, 5);
  $("#recent-list").classList.toggle("empty-state", !recent.length);
  $("#recent-list").innerHTML = recent.length ? recent.map(scan => (
    `<div class="recent-item"><div><b>${safe(scan.hostname)}</b><small>${safe(scan.country)} / ${safe(scan.sector)} / ${safe(date(scan.scan_time))}</small></div><span class="grade grade-${safe(isScored(scan) ? scan.scores?.grade : "NA")}">${safe(isScored(scan) ? scan.scores?.grade : "N/A")}</span></div>`
  )).join("") : "No scans yet.";
}

function renderResults() {
  const search = $("#result-search").value.trim().toLowerCase();
  const country = $("#filter-country").value;
  const sector = $("#filter-sector").value;
  const rows = state.scans.filter(scan => (
    (!search || scan.hostname.toLowerCase().includes(search))
    && (!country || scan.country === country)
    && (!sector || scan.sector === sector)
  ));
  $("#results-body").innerHTML = rows.map(scan => `<tr data-scan-id="${safe(scan.id)}">
    <td class="target-cell"><b>${safe(scan.hostname)}</b><small>:${safe(scan.port)}</small></td>
    <td>${safe(scan.country)}<br><small>${safe(scan.sector)}</small></td>
    <td><span class="score-dot">${isScored(scan) ? number(scan.scores?.certificate) : "--"}</span></td>
    <td>${isScored(scan) ? number(scan.scores?.configuration) : "--"}</td>
    <td><b>${isScored(scan) ? number(scan.scores?.overall) : "Not scored"}</b></td>
    <td><span class="grade grade-${safe(isScored(scan) ? scan.scores?.grade : "NA")}">${safe(isScored(scan) ? scan.scores?.grade : "N/A")}</span></td>
    <td>${safe(date(scan.scan_time))}</td>
    <td><button class="row-detail-prompt" type="button">Click to view detailed results</button></td>
  </tr>`).join("");
  $("#results-empty").classList.toggle("hidden", rows.length > 0);
  $$("#results-body tr").forEach(row => row.addEventListener("click", () => openDetail(row.dataset.scanId)));
}

function replaceSelectOptions(select, firstLabel, values) {
  const previous = select.value;
  select.innerHTML = `<option value="">${safe(firstLabel)}</option>${values.map(value => `<option value="${safe(value)}">${safe(value)}</option>`).join("")}`;
  if (values.includes(previous)) select.value = previous;
}

function updateDataLabelControls() {
  const countries = [...new Set(state.scans.map(scan => String(scan.country || "").trim()).filter(Boolean))].sort((left, right) => left.localeCompare(right));
  const sectors = [...new Set(state.scans.map(scan => String(scan.sector || "").trim()).filter(Boolean))].sort((left, right) => left.localeCompare(right));
  replaceSelectOptions($("#filter-country"), "All countries", countries);
  replaceSelectOptions($("#filter-sector"), "All sectors", sectors);
  $("#country-labels").innerHTML = countries.map(value => `<option value="${safe(value)}"></option>`).join("");
  $("#sector-labels").innerHTML = sectors.map(value => `<option value="${safe(value)}"></option>`).join("");
}

async function refreshJobs() {
  try {
    const data = await api("/api/jobs");
    state.jobs = data.items;
    renderJobs();
  } catch (error) {
    toast(error.message, true);
  }
}

function renderJobs() {
  const target = $("#jobs-list");
  target.classList.toggle("empty-state", !state.jobs.length);
  target.innerHTML = state.jobs.length ? state.jobs.map(job => {
    const done = job.completed + job.failed;
    const status = safe(job.status.replaceAll("_", " ").toUpperCase());
    const current = job.current_target ? `Current: ${safe(job.current_target)}` : `Created ${safe(date(job.created_at))}`;
    return `<div class="job-item"><div class="job-top"><div><b>${status}</b><small>${safe(job.message || "")}</small></div><small>${done} / ${job.total} / ${job.percent}%</small></div><div class="progress"><i style="width:${job.percent}%"></i></div><small>${current}${job.failed ? ` / ${job.failed} failed` : ""}</small></div>`;
  }).join("") : "No scan jobs yet.";
  $("#start-batch").disabled = state.jobs.some(job => ["queued","running"].includes(job.status)) || !state.batchTargets.length;
}

function renderAnalysis() {
  const analysis = state.analysis;
  if (!analysis) return;
  populateComparisonControls();
  const comparison = analysis.comparison || {};
  const selection = analysis.selection || {};
  const available = analysis.available_labels || {};
  $("#dataset-note").textContent = `${analysis.total_collected || 0} unique observations / ${analysis.unlabelled_observations || 0} without complete comparison labels. CSV labels: ${(available.country || []).length} country and ${(available.sector || []).length} sector values.`;
  $("#conclusion-status").textContent = (comparison.status || "awaiting_selection").replaceAll("_", " ").toUpperCase();
  $("#conclusion-text").textContent = comparison.conclusion || "Select two labels to begin the analysis.";
  $("#comparison-eyebrow").textContent = selection.compare_field
    ? `${selection.compare_field.toUpperCase()} LABEL COMPARISON`
    : "USER-DEFINED COMPARISON";
  $("#conclusion-detail").textContent = `${analysis.duplicate_observations_excluded || 0} older duplicate(s) excluded. Results require 2 observations per cell and are marked stable at 10 per cell.`;

  const overall = analysis.overall_summary || {};
  const overallCard = `<article class="panel group-card"><span class="eyebrow">ALL COMPLETED SITES</span><strong>${number(overall.mean)}</strong><small>MEAN TLS SCORE</small><div class="group-meta"><span><b>${overall.n || 0}</b><small> SITES</small></span><span><b>${number(overall.tls13_rate, "%")}</b><small> TLS 1.3</small></span></div></article>`;
  const selectedCards = (analysis.group_cards || []).map(card => {
    const summary = card.summary || {};
    return `<article class="panel group-card"><span class="eyebrow">${safe(card.group)} / ${safe(card.stratum)}</span><strong>${number(summary.mean)}</strong><small>MEAN TLS SCORE</small><div class="group-meta"><span><b>${summary.n || 0}</b><small> SITES</small></span><span><b>${number(summary.tls13_rate, "%")}</b><small> TLS 1.3</small></span></div></article>`;
  }).join("");
  $("#analysis-groups").innerHTML = overallCard + selectedCards;

  const ready = analysis.comparison_ready && Object.keys(analysis.selected_summaries || {}).length === 2;
  $("#comparison-result-panel").classList.toggle("hidden", !ready);
  if (ready) {
    const groupA = selection.group_a;
    const groupB = selection.group_b;
    $("#comparison-title").textContent = `${groupA} vs ${groupB}`;
    $("#comparison-bars").innerHTML = [groupA, groupB].map(name => {
      const summary = analysis.selected_summaries[name] || {};
      return `<div class="bar-row"><b>${safe(name)}</b><div class="bar-track"><div class="bar-fill" style="width:${summary.mean || 0}%"></div></div><strong>${number(summary.mean)}</strong></div>`;
    }).join("");
    const interval = comparison.bootstrap_ci_95 || [null, null];
    $("#comparison-stat-list").innerHTML = `<dt>${safe(groupA)} - ${safe(groupB)}</dt><dd>${number(comparison.observed_difference)} pts</dd><dt>Two-sided p-value</dt><dd>${comparison.p_value ?? "--"}</dd><dt>Cliff's delta</dt><dd>${comparison.cliffs_delta ?? "--"}</dd><dt>Stratified bootstrap 95% CI</dt><dd>[${number(interval[0])}, ${number(interval[1])}]</dd><dt>Control field</dt><dd>${safe(selection.stratum_field)}</dd><dt>Selected strata</dt><dd>${safe((selection.strata || []).join(", "))}</dd><dt>Stability threshold</dt><dd>${analysis.comparison_stable ? "Met" : "Not met"}</dd>`;
  }

  const labels = [["critical","Critical"],["warning","Warning"],["info","Informational"],["pass","Passed checks"]];
  $("#finding-bars").innerHTML = labels.map(([key, label]) => `<div class="severity"><b>${analysis.finding_counts?.[key] || 0}</b><small>${label}</small></div>`).join("");
}

function populateComparisonControls() {
  const analysis = state.analysis;
  if (!analysis) return;
  const selection = state.analysisSelection;
  $("#compare-field").value = selection.compareField;
  const labels = analysis.available_labels?.[selection.compareField] || [];
  const groupASelect = $("#group-a");
  const groupBSelect = $("#group-b");
  replaceSelectOptions(groupASelect, "Select Group A", labels);
  replaceSelectOptions(groupBSelect, "Select Group B", labels);
  groupASelect.disabled = !selection.compareField;
  groupBSelect.disabled = !selection.compareField;
  groupASelect.value = labels.includes(selection.groupA) ? selection.groupA : "";
  groupBSelect.value = labels.includes(selection.groupB) ? selection.groupB : "";

  const stratumField = selection.compareField === "country" ? "sector" : selection.compareField === "sector" ? "country" : "";
  const stratumLabels = analysis.available_labels?.[stratumField] || [];
  $("#strata-builder").classList.toggle("hidden", !selection.compareField);
  $("#strata-help").textContent = stratumField ? `Control for ${stratumField}. Select one or more labels.` : "";
  $("#strata-choices").innerHTML = stratumLabels.map(value => (
    `<label><input type="checkbox" data-analysis-stratum value="${safe(value)}"${selection.strata.includes(value) ? " checked" : ""}> ${safe(value)}</label>`
  )).join("");
  $$("[data-analysis-stratum]").forEach(input => input.addEventListener("change", updateAnalysisStrata));
}

function valueRows(values) {
  return Object.entries(values).map(([key, value]) => {
    const display = Array.isArray(value)
      ? value.join(", ") || "--"
      : typeof value === "object" && value !== null ? JSON.stringify(value) : value;
    return `<div class="kv"><dt>${safe(key.replaceAll("_", " "))}</dt><dd>${safe(display)}</dd></div>`;
  }).join("");
}

async function openDetail(id) {
  try {
    const scan = await api(`/api/scans/${encodeURIComponent(id)}`);
    $("#detail-title").textContent = `${scan.hostname}:${scan.port}`;
    const scores = scan.scores || {};
    const certificate = scan.certificate || {};
    const key = scan.key_exchange || {};
    const protocols = scan.protocols || {};
    const ciphers = scan.ciphers || {};
    const scoreCards = [
      ["Certificate", scores.certificate],
      ["Protocols", scores.protocol],
      ["Key exchange", scores.key_exchange],
      ["Cipher", scores.cipher],
      ["Overall", isScored(scan) ? `${scores.overall} / ${scores.grade}` : "Not scored / N/A"],
    ];
    const findings = (scan.findings || []).map(finding => (
      `<div class="finding ${safe(finding.severity)}"><b>${safe(finding.title || finding.code)}</b><span>${safe(finding.detail || finding.message || "")}</span>${finding.remediation ? `<span>Fix: ${safe(finding.remediation)}</span>` : ""}</div>`
    )).join("") || '<p class="form-note">No findings recorded.</p>';
    $("#detail-content").innerHTML = `<div class="detail-body">
      <div class="score-cards">${scoreCards.map(([label, value]) => `<div class="mini-score"><b>${safe(value ?? "--")}</b><span>${label}</span></div>`).join("")}</div>
      <div class="evidence-grid">
        <section class="evidence-card"><h3>Certificate identity</h3>${valueRows({common_name:certificate.common_name,SAN_DNS:certificate.san_dns,issuer:certificate.issuer,serial_number:certificate.serial_number,SHA1_thumbprint:certificate.fingerprint_sha1,SHA256_thumbprint:certificate.fingerprint_sha256})}</section>
        <section class="evidence-card"><h3>Certificate assurance</h3>${valueRows({trusted:certificate.trust_valid,hostname_matches:certificate.hostname_valid,valid_from:certificate.not_before,valid_until:certificate.not_after,days_remaining:certificate.days_remaining,signature_algorithm:certificate.signature_algorithm,public_key:`${certificate.public_key_type || "--"} ${certificate.public_key_bits || ""}`,chain_complete:certificate.chain_complete,OCSP_stapling:certificate.ocsp_stapling,revocation_status:certificate.revocation_status,CT_SCTs:certificate.ct_sct_count})}</section>
        <section class="evidence-card"><h3>Protocols</h3><div class="protocol-list">${Object.entries(protocols).map(([name, status]) => `<div class="protocol-item status-${safe(status)}"><b>${safe(name)}</b><span>${safe(status === "unsupported" || status === "not_supported" ? "not supported" : status === "error" ? "probe error" : status)}</span></div>`).join("") || "No protocol evidence"}</div></section>
        <section class="evidence-card"><h3>Connection and key exchange</h3>${valueRows({key_exchange:key.method,key_bits:key.bits,forward_secrecy:key.forward_secrecy,minimum_DHE_bits:key.minimum_dhe_bits,maximum_DHE_bits:key.maximum_dhe_bits,observed_exchanges:key.observed,secure_renegotiation:scan.secure_renegotiation,compression:scan.compression,ALPN:scan.alpn})}</section>
        <section class="evidence-card"><h3>Cipher inventory</h3>${valueRows({negotiated:ciphers.negotiated,negotiated_bits:ciphers.negotiated_bits,weakest_bits:ciphers.weakest_bits,strongest_bits:ciphers.strongest_bits,accepted:ciphers.accepted,accepted_details:ciphers.accepted_details,attempted:ciphers.attempted,enumeration_complete:ciphers.enumeration_complete})}</section>
        <section class="evidence-card"><h3>Findings and remediation</h3><div class="finding-list">${findings}</div></section>
      </div>
      <section class="evidence-card"><h3>Raw OpenSSL evidence excerpt</h3><pre class="raw">${safe(typeof scan.raw_evidence === "object" ? JSON.stringify(scan.raw_evidence, null, 2) : scan.raw_evidence || "Not available.")}</pre></section>
      <p class="form-note">Scanned ${safe(date(scan.scan_time))} / complete assessment / source ${safe(scan.source)} / ${safe((scan.errors || []).join("; ") || "no collection errors")}</p>
    </div>`;
    $("#detail-dialog").showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quote = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    const next = text[index + 1];
    if (character === '"' && quote && next === '"') {
      field += '"';
      index += 1;
    } else if (character === '"') {
      quote = !quote;
    } else if (character === "," && !quote) {
      row.push(field.trim());
      field = "";
    } else if ((character === "\n" || character === "\r") && !quote) {
      if (character === "\r" && next === "\n") index += 1;
      row.push(field.trim());
      if (row.some(Boolean)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }
  row.push(field.trim());
  if (row.some(Boolean)) rows.push(row);
  if (!rows.length) return [];
  const aliases = {host:"hostname", domain:"hostname", website:"hostname", url:"hostname"};
  const headers = rows[0].map(value => {
    const normalized = value.replace(/^\uFEFF/, "").toLowerCase().trim().replaceAll(" ", "_");
    return aliases[normalized] || normalized;
  });
  const hasHostnameHeader = headers.includes("hostname");
  if (!hasHostnameHeader) {
    if (rows.some(values => values.slice(1).some(Boolean))) {
      throw new Error("Use a one-column hostname list, or include a hostname column header");
    }
    return rows
      .map(values => ({hostname:values[0].replace(/^\uFEFF/, "").trim(), country:"", sector:"", source:"one-column-csv"}))
      .filter(target => target.hostname);
  }
  return rows.slice(1)
    .map(values => Object.fromEntries(headers.map((header, index) => [header, values[index] || ""])))
    .filter(target => target.hostname);
}

async function submitSingle(event) {
  event.preventDefault();
  const submitButton = event.currentTarget.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  const originalLabel = submitButton.textContent;
  submitButton.textContent = "Queueing...";
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  payload.port = Number(payload.port);
  try {
    const data = await api("/api/scan", {method:"POST", body:JSON.stringify(payload)});
    toast(`Full assessment queued: ${data.job_id.slice(0, 8)}`);
    event.currentTarget.reset();
    event.currentTarget.port.value = 443;
    refreshJobs();
  } catch (error) {
    toast(error.message, true);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = originalLabel;
  }
}

async function submitBatch() {
  const submitButton = $("#start-batch");
  submitButton.disabled = true;
  const originalLabel = submitButton.textContent;
  submitButton.textContent = "Queueing...";
  try {
    const targets = state.batchTargets;
    if (!targets.length) throw new Error("No valid target rows found");
    const data = await api("/api/jobs", {method:"POST", body:JSON.stringify({targets})});
    toast(`${targets.length} full assessments queued: ${data.job_id.slice(0, 8)}`);
    await refreshJobs();
  } catch (error) {
    toast(error.message, true);
  } finally {
    submitButton.disabled = state.jobs.some(job => ["queued","running"].includes(job.status)) || !state.batchTargets.length;
    submitButton.textContent = originalLabel;
  }
}

function resetFileSelection() {
  state.batchFileText = "";
  state.batchTargets = [];
  $("#csv-file").value = "";
  $("#file-confirm").classList.remove("ready", "error");
  $("#file-status-label").textContent = "WAITING FOR FILE";
  $("#file-name").textContent = "No CSV selected";
  $("#file-summary").textContent = "Choose a study file above.";
  $("#start-batch").disabled = true;
}

async function handleCsvFile(file) {
  if (!file) return;
  const confirmation = $("#file-confirm");
  try {
    const text = await file.text();
    const targets = parseCSV(text);
    if (!targets.length) throw new Error("The CSV contains no valid target rows");
    state.batchFileText = text;
    state.batchTargets = targets;
    const groups = new Map();
    targets.forEach(target => {
      const label = [target.country, target.sector].filter(Boolean).join(" / ") || "Unlabelled";
      groups.set(label, (groups.get(label) || 0) + 1);
    });
    const groupSummary = [...groups].map(([label, count]) => `${label}: ${count}`).join(" / ");
    confirmation.classList.remove("error");
    confirmation.classList.add("ready");
    $("#file-status-label").textContent = "CSV READY TO RUN";
    $("#file-name").textContent = file.name;
    $("#file-summary").textContent = `${targets.length.toLocaleString("en-SG")} targets / ${(file.size / 1024).toFixed(1)} KB${groupSummary ? ` / ${groupSummary}` : ""}`;
    $("#start-batch").disabled = state.jobs.some(job => ["queued","running"].includes(job.status));
    toast(`${file.name} loaded successfully / ${targets.length.toLocaleString("en-SG")} targets`);
  } catch (error) {
    resetFileSelection();
    confirmation.classList.add("error");
    $("#file-status-label").textContent = "CSV COULD NOT BE READ";
    $("#file-name").textContent = file.name;
    $("#file-summary").textContent = error.message;
    toast(error.message, true);
  }
}

async function resetProject() {
  if (!confirm("Reset this local project? All scan evidence and task history will be permanently deleted.")) return;
  try {
    const result = await api("/api/data/clear", {method:"POST", body:JSON.stringify({confirm:"DELETE ALL"})});
    state.analysisSelection = {compareField:"", groupA:"", groupB:"", strata:[]};
    $("#compare-field").value = "";
    resetFileSelection();
    await refreshAll();
    navigate("overview");
    const counts = result.reset || {};
    toast(`Project reset / ${counts.scans || 0} scans and ${counts.jobs || 0} tasks removed`);
  } catch (error) {
    toast(error.message, true);
  }
}

function updateCompareField(event) {
  const compareField = event.target.value;
  state.analysisSelection = {
    compareField,
    groupA:"",
    groupB:"",
    strata:[],
  };
  populateComparisonControls();
  refreshAnalysis().catch(error => toast(error.message, true));
}

function updateComparisonGroups() {
  state.analysisSelection.groupA = $("#group-a").value;
  state.analysisSelection.groupB = $("#group-b").value;
  if (state.analysisSelection.groupA && state.analysisSelection.groupA === state.analysisSelection.groupB) {
    state.analysisSelection.groupB = "";
    $("#group-b").value = "";
    toast("Group A and Group B must use different labels", true);
  }
  refreshAnalysis().catch(error => toast(error.message, true));
}

function updateAnalysisStrata() {
  state.analysisSelection.strata = $$("[data-analysis-stratum]:checked").map(input => input.value);
  refreshAnalysis().catch(error => toast(error.message, true));
}

function bindEvents() {
  $$("[data-route]").forEach(element => element.addEventListener("click", event => {
    event.preventDefault();
    navigate(element.dataset.route);
  }));
  $("#refresh-all").addEventListener("click", () => refreshAll().then(() => toast("Local data refreshed")));
  $("#single-form").addEventListener("submit", submitSingle);
  $("#start-batch").addEventListener("click", submitBatch);
  $("#refresh-jobs").addEventListener("click", refreshJobs);
  $("#csv-file").addEventListener("change", event => handleCsvFile(event.target.files[0]));
  $("#change-file").addEventListener("click", () => $("#csv-file").click());
  const dropZone = $(".drop-zone");
  ["dragenter","dragover"].forEach(name => dropZone.addEventListener(name, event => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  }));
  ["dragleave","drop"].forEach(name => dropZone.addEventListener(name, event => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  }));
  dropZone.addEventListener("drop", event => handleCsvFile(event.dataTransfer.files[0]));
  ["#result-search","#filter-country","#filter-sector"].forEach(selector => (
    $(selector).addEventListener(selector.includes("search") ? "input" : "change", renderResults)
  ));
  $("#compare-field").addEventListener("change", updateCompareField);
  $("#group-a").addEventListener("change", updateComparisonGroups);
  $("#group-b").addEventListener("change", updateComparisonGroups);
  $("#close-detail").addEventListener("click", () => $("#detail-dialog").close());
  $("#detail-dialog").addEventListener("click", event => {
    if (event.target === $("#detail-dialog")) $("#detail-dialog").close();
  });
  $$("[data-reset-project]").forEach(button => button.addEventListener("click", resetProject));
}

bindEvents();
navigate(location.hash.slice(1) || "overview");
refreshAll();
setInterval(() => {
  if (state.jobs.some(job => ["queued","running"].includes(job.status))) {
    refreshJobs();
    refreshScans();
    refreshAnalysis();
  }
}, 2500);
