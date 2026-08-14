(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.CsvTargets = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const HEADER_ALIASES = {host:"hostname", domain:"hostname", website:"hostname", url:"hostname"};
  const SCAN_FIELDS = ["hostname", "country", "sector", "source", "port"];
  const BACKEND_DOMAIN = /^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i;

  function readRows(text) {
    const rows = [];
    let row = [];
    let field = "";
    let quoted = false;
    let line = 1;
    let rowLine = 1;
    for (let index = 0; index < text.length; index += 1) {
      const character = text[index];
      const next = text[index + 1];
      if (character === '"' && quoted && next === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') {
        quoted = !quoted;
      } else if (character === "," && !quoted) {
        row.push(field.trim());
        field = "";
      } else if ((character === "\n" || character === "\r") && !quoted) {
        if (character === "\r" && next === "\n") index += 1;
        row.push(field.trim());
        if (row.some(Boolean)) rows.push({line:rowLine, values:row});
        row = [];
        field = "";
        line += 1;
        rowLine = line;
      } else {
        field += character;
        if (character === "\n") line += 1;
      }
    }
    if (quoted) throw new Error(`CSV has an unclosed quoted field near line ${rowLine}`);
    row.push(field.trim());
    if (row.some(Boolean)) rows.push({line:rowLine, values:row});
    return rows;
  }

  function normalizeHeader(value) {
    const normalized = value.replace(/^\uFEFF/, "").toLowerCase().trim().replaceAll(" ", "_");
    return HEADER_ALIASES[normalized] || normalized;
  }

  function validHostnameOrUrl(value) {
    if (!value || /\s/.test(value)) return false;
    try {
      const parsed = new URL(value.includes("://") ? value : `https://${value}`);
      const hostname = parsed.hostname;
      const validAddress = hostname.startsWith("[") && hostname.endsWith("]");
      return ["http:", "https:"].includes(parsed.protocol)
        && Boolean(hostname)
        && (validAddress || BACKEND_DOMAIN.test(hostname));
    } catch (_) {
      return false;
    }
  }

  function targetIdentity(target) {
    const parsed = new URL(target.hostname.includes("://") ? target.hostname : `https://${target.hostname}`);
    const port = String(target.port || parsed.port || "443");
    if (!target.port && parsed.port) target.port = parsed.port;
    return `${parsed.hostname.toLowerCase().replace(/\.$/, "")}:${port}`;
  }

  function parseTargetCSV(text) {
    const rows = readRows(String(text || ""));
    if (!rows.length) throw new Error("CSV contains no target rows");
    const headers = rows[0].values.map(normalizeHeader);
    const labelled = headers.includes("hostname");
    if (new Set(headers).size !== headers.length) throw new Error("CSV contains a duplicate header");
    const ignoredHeaders = labelled ? headers.filter(header => !SCAN_FIELDS.includes(header)) : [];
    if (!labelled && rows.some(row => row.values.slice(1).some(Boolean))) {
      throw new Error("Use a one-column hostname list, or include a hostname column header");
    }
    const dataRows = labelled ? rows.slice(1) : rows;
    const invalid = [];
    const duplicates = [];
    const targets = [];
    const seen = new Set();
    for (const row of dataRows) {
      if (labelled && row.values.length > headers.length) {
        invalid.push({line:row.line, reason:"Row has more columns than the header"});
        continue;
      }
      const rawTarget = labelled
        ? Object.fromEntries(headers.map((header, index) => [header, row.values[index] || ""]))
        : {hostname:row.values[0].replace(/^\uFEFF/, "").trim(), country:"", sector:"", source:"one-column-csv"};
      const target = Object.fromEntries(
        SCAN_FIELDS.filter(field => Object.prototype.hasOwnProperty.call(rawTarget, field))
          .map(field => [field, rawTarget[field] || ""])
      );
      target.hostname = String(target.hostname || "").trim();
      if (!target.hostname) {
        invalid.push({line:row.line, reason:"Hostname is empty"});
        continue;
      }
      if (!validHostnameOrUrl(target.hostname)) {
        invalid.push({line:row.line, reason:"Hostname or URL is invalid"});
        continue;
      }
      if (target.port && (!/^\d+$/.test(String(target.port)) || Number(target.port) < 1 || Number(target.port) > 65535)) {
        invalid.push({line:row.line, reason:"Port must be an integer from 1 to 65535"});
        continue;
      }
      const key = targetIdentity(target);
      if (seen.has(key)) {
        duplicates.push({line:row.line, hostname:target.hostname});
        continue;
      }
      seen.add(key);
      targets.push(target);
    }
    if (!targets.length) throw new Error("CSV contains no valid target rows");
    return {targets, invalid, duplicates, ignoredHeaders};
  }

  return {parseTargetCSV};
});
