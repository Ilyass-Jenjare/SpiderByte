import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import VulnerabilityDrawer from "../components/dashboard/VulnerabilityDrawer";
import VulnerabilityDetails from "../components/dashboard/VulnerabilityDetails";
import { useScan } from "../context/ScanContext";

const MODULE_ORDER = ["sql_injection", "nuclei", "nmap", "headers", "ssl", "legacy"];
const MODULE_LABELS = {
  sql_injection: "SQLi",
  nuclei: "Nuclei",
  nmap: "Nmap",
  headers: "Headers",
  ssl: "SSL",
  legacy: "Legacy",
};

// Poids des sévérités pour forcer le tri (High en haut, Info en bas)
const SEVERITY_RANK = { high: 4, medium: 3, low: 2, info: 1 };

function normalizeSeverity(value) {
  const normalized = String(value || "info").toLowerCase();
  if (normalized === "critical") return "high";
  if (normalized === "moderate") return "medium";
  if (normalized === "informational") return "info";
  if (["high", "medium", "low", "info"].includes(normalized)) return normalized;
  return "info";
}

function severityBadgeTone(severity) {
  if (severity === "high") return "border-red-400/50 bg-red-500/20 text-red-200";
  if (severity === "medium") return "border-orange-400/50 bg-orange-500/20 text-orange-200";
  if (severity === "low") return "border-emerald-400/50 bg-emerald-500/20 text-emerald-200";
  return "border-sky-400/50 bg-sky-500/20 text-sky-200";
}

function formatDateTime(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function formatStatus(status) {
  return String(status || "unknown").trim().toUpperCase() || "UNKNOWN";
}

function isFinishedStatus(status) {
  return formatStatus(status) === "FINISHED";
}

function emptySummary() {
  return { total: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizePayloads(details) {
  const payloads = Array.isArray(details?.payloads) ? [...details.payloads] : [];
  if (details?.payload) payloads.unshift(details.payload);
  const seen = new Set();
  const unique = [];
  payloads.forEach((payload) => {
    const normalized = String(payload || "").trim();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    unique.push(normalized);
  });
  return unique;
}

function SummaryCard({ label, value, tone }) {
  return (
    <article className="glass-panel soft-ring rounded-2xl p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</p>
      <p className={`mt-2 text-2xl font-semibold ${tone}`}>{value}</p>
    </article>
  );
}

function summarizeFromFindings(findings) {
  const summary = { total: findings.length, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    const severity = normalizeSeverity(finding.severity);
    if (summary[severity] !== undefined) summary[severity] += 1;
    else summary.info += 1;
  });
  return summary;
}

function normalizeSummary(summary, vulnerabilities) {
  const fallback = summarizeFromFindings(vulnerabilities);
  if (!summary || typeof summary !== "object") return fallback;
  return {
    total: Number(summary.total ?? fallback.total) || 0,
    high: Number(summary.high ?? fallback.high) || 0,
    medium: Number(summary.medium ?? fallback.medium) || 0,
    low: Number(summary.low ?? fallback.low) || 0,
    info: Number(summary.info ?? fallback.info) || 0,
  };
}

function normalizeLegacyToFinding(vulnerability, target) {
  return {
    id: vulnerability.id || `legacy-${Date.now()}`,
    module: "legacy",
    moduleLabel: "Legacy Finding",
    name: vulnerability.title || "Legacy vulnerability",
    vulnerabilityType: String(vulnerability.severity || "info").toUpperCase(),
    severity: vulnerability.severity || "info",
    description: vulnerability.description || "Imported from previous dashboard format.",
    targetUrl: target,
    details: {
      payload: vulnerability.payload || "",
      request: vulnerability.request || "",
      response: vulnerability.response || "",
      recommendation: vulnerability.recommendation || "Review manually.",
    },
  };
}

function ScanCard({ scan, isActive, onSelect }) {
  const vulnerabilities = Array.isArray(scan.findings) ? scan.findings : [];
  const summary = normalizeSummary(scan.summary, vulnerabilities);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`glass-panel soft-ring w-full rounded-2xl border p-5 text-left transition duration-300 hover:-translate-y-0.5 ${
        isActive ? "border-yellow-400/60 ring-2 ring-yellow-400/30" : "border-zinc-800 hover:border-zinc-600"
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-[0.14em] text-zinc-500">Target</p>
          <p className="font-mono text-sm text-zinc-100">{scan.target || "-"}</p>
        </div>
        <span className="rounded-full border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-200">
          {formatStatus(scan.status)}
        </span>
      </div>

      <div className="mt-4 grid gap-3 text-sm text-zinc-300 sm:grid-cols-2">
        <p><span className="text-zinc-500">Date:</span> {formatDateTime(scan.createdAt)}</p>
        <p><span className="text-zinc-500">Total vulnerabilities:</span> {summary.total}</p>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <span className="rounded-full border border-red-400/40 bg-red-500/10 px-3 py-1 text-xs text-red-200">HIGH {summary.high}</span>
        <span className="rounded-full border border-orange-400/40 bg-orange-500/10 px-3 py-1 text-xs text-orange-200">MEDIUM {summary.medium}</span>
        <span className="rounded-full border border-emerald-400/40 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-200">LOW {summary.low}</span>
        <span className="rounded-full border border-sky-400/40 bg-sky-500/10 px-3 py-1 text-xs text-sky-200">INFO {summary.info}</span>
      </div>
    </button>
  );
}

function ScanMetaField({ label, value, mono = false }) {
  return (
    <article className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
      <p className="text-xs uppercase tracking-[0.14em] text-zinc-500">{label}</p>
      <p className={`mt-1 text-sm text-zinc-100 ${mono ? "font-mono" : ""}`}>{value || "-"}</p>
    </article>
  );
}

function GroupedVulnerabilityCard({ vulnerability, onOpen }) {
  const severity = normalizeSeverity(vulnerability.severity);
  const badgeTone = severityBadgeTone(severity);
  const payloads = normalizePayloads(vulnerability.details || {});
  const payloadCount = Math.max(toNumber(vulnerability?.details?.countPayloads, payloads.length), payloads.length);
  const isSqlFinding = vulnerability.module === "sql_injection";

  return (
    <article className="w-full rounded-xl border border-zinc-800 bg-zinc-950/70 p-4 text-left transition duration-300 hover:border-zinc-600 hover:bg-zinc-900">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-3">
          <h4 className="text-base font-semibold text-white">{vulnerability.displayName || vulnerability.name}</h4>
          {vulnerability.count > 1 && (
            <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs font-semibold text-zinc-300">
              x{vulnerability.count} instances
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${badgeTone}`}>{severity}</span>
          <button
            type="button"
            onClick={() => onOpen(vulnerability)}
            className="rounded-lg border border-zinc-700 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-200 transition duration-300 hover:border-zinc-500 hover:bg-zinc-800"
          >
            View details
          </button>
        </div>
      </div>
      
      <div className="mt-2 flex items-center gap-3 text-xs">
        <span className="uppercase tracking-wide text-zinc-500">{vulnerability.vulnerabilityType || "General"}</span>
        <span className="text-zinc-600">•</span>
        <span className="text-zinc-400">{vulnerability.moduleLabel}</span>
      </div>

      <p className="mt-3 text-sm text-zinc-300">{vulnerability.description || "No description."}</p>
      
      {isSqlFinding ? (
        <div className="mt-3 rounded-lg border border-zinc-800 bg-zinc-900/70 p-3">
          <p className="text-xs text-zinc-300">{payloadCount} payload(s) exploitable(s)</p>
          {payloads.length ? (
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-zinc-400 transition hover:text-zinc-200">
                Show payload list ({payloads.length} unique)
              </summary>
              <ul className="mt-2 space-y-1">
                {payloads.map((payload, index) => (
                  <li key={`payload-${index}`} className="rounded-md border border-zinc-800 bg-zinc-950/80 px-2 py-1 font-mono text-xs text-zinc-300">
                    {payload}
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </div>
      ) : null}
      
     <p className="mt-3 truncate font-mono text-xs text-zinc-400">Target: {vulnerability.targetUrl || "-"}</p>
    </article>
  );
}

export default function Dashboard() {
  const { scans, activeScan, activeScanId, selectScan } = useScan();
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  
  // NOUVEAU : État pour gérer le mode de vue (Par Sévérité ou Par Module)
  const [viewMode, setViewMode] = useState("severity"); 

  const isFinished = isFinishedStatus(activeScan?.status);

  const rawVulnerabilities = useMemo(() => {
    if (!activeScan) return [];
    if (!isFinishedStatus(activeScan.status)) return [];
    if (Array.isArray(activeScan.findings)) return activeScan.findings;
    if (Array.isArray(activeScan.vulnerabilities)) {
      return activeScan.vulnerabilities.map((item) => normalizeLegacyToFinding(item, activeScan.target || "-"));
    }
    return [];
  }, [activeScan]);

  const scanSummary = useMemo(() => {
    if (!isFinished) return emptySummary();
    return normalizeSummary(activeScan?.summary, rawVulnerabilities);
  }, [activeScan?.summary, isFinished, rawVulnerabilities]);
  
  const sqlSummary = useMemo(() => {
    if (!isFinished) {
      return { totalVulnerabilities: 0, totalPayloads: 0 };
    }
    const sqlFindings = rawVulnerabilities.filter((v) => v.module === "sql_injection");
    const derivedPayloads = sqlFindings.reduce((sum, v) => {
      const payloads = normalizePayloads(v.details || {});
      return sum + Math.max(toNumber(v?.details?.countPayloads, payloads.length), payloads.length);
    }, 0);
    return {
      totalVulnerabilities: Math.max(toNumber(activeScan?.sqlMetrics?.totalVulnerabilities, sqlFindings.length), sqlFindings.length),
      totalPayloads: Math.max(toNumber(activeScan?.sqlMetrics?.totalPayloads, derivedPayloads), derivedPayloads),
    };
  }, [activeScan?.sqlMetrics, isFinished, rawVulnerabilities]);

  // NOUVEAU : Dédoublonnage intelligent des alertes
  const aggregatedVulnerabilities = useMemo(() => {
    const map = new Map();
    rawVulnerabilities.forEach((v) => {
      // On regroupe par module et par nom de base (on enlève l'URL du nom pour les grouper)
      const baseName = (v.name || "").split(' · ')[0];
      const key = `${v.module}-${baseName}`;

      if (!map.has(key)) {
        map.set(key, { ...v, displayName: baseName, count: 1, endpoints: new Set([v.targetUrl]) });
      } else {
        const existing = map.get(key);
        existing.count += 1;
        if (v.targetUrl) existing.endpoints.add(v.targetUrl);
      }
    });

    return Array.from(map.values()).map(v => ({
      ...v,
      endpointsList: Array.from(v.endpoints) // Utilisé dans les détails
    }));
  }, [rawVulnerabilities]);

  // NOUVEAU : Groupement en fonction du viewMode choisi
  const groupedVulnerabilities = useMemo(() => {
    const groups = new Map();
    
    aggregatedVulnerabilities.forEach((v) => {
      const groupKey = viewMode === "severity" ? normalizeSeverity(v.severity) : (v.module || "legacy");
      if (!groups.has(groupKey)) groups.set(groupKey, []);
      groups.get(groupKey).push(v);
    });

    // Tri à l'intérieur de chaque groupe par Sévérité
    groups.forEach((vulns) => {
      vulns.sort((a, b) => SEVERITY_RANK[normalizeSeverity(b.severity)] - SEVERITY_RANK[normalizeSeverity(a.severity)]);
    });

    const ordered = [];
    if (viewMode === "severity") {
      ["high", "medium", "low", "info"].forEach(sev => {
        if (groups.has(sev)) ordered.push([sev.toUpperCase(), groups.get(sev)]);
      });
    } else {
      MODULE_ORDER.forEach(mod => {
        if (groups.has(mod)) ordered.push([MODULE_LABELS[mod] || mod, groups.get(mod)]);
      });
    }

    return ordered;
  }, [aggregatedVulnerabilities, viewMode]);

  useEffect(() => {
    setSelectedVulnerability(null);
  }, [activeScan?.id]);

  if (!scans.length) {
    return (
      <section className="space-y-6">
        <h1 className="text-3xl font-semibold text-white">Reports Dashboard</h1>
        <article className="glass-panel soft-ring rounded-2xl p-6">
          <p className="text-zinc-300">No scan results yet. Launch your first scan from the landing page.</p>
          <Link to="/" className="accent-button mt-4 inline-flex">Go to Scanner</Link>
        </article>
      </section>
    );
  }

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold text-white">Reports Dashboard</h1>
        <p className="text-sm text-zinc-400">List of your scans first, then detailed findings per selected scan.</p>
      </div>

      <article className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold text-white">1. Your scans</h2>
          <span className="rounded-full border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-300">{scans.length} scan(s)</span>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {scans.map((scan) => (
            <ScanCard key={scan.id} scan={scan} isActive={scan.id === activeScanId} onSelect={() => selectScan(scan.id)} />
          ))}
        </div>
      </article>

      {activeScan ? (
        <article className="space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-xl font-semibold text-white">2. Scan details</h2>
            <span className="rounded-full border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-200">
              {formatStatus(activeScan.status)}
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <ScanMetaField label="Target" value={activeScan.target} mono />
            <ScanMetaField label="Created At" value={formatDateTime(activeScan.createdAt)} />
            <ScanMetaField label="Duration" value={activeScan.executionTime || "-"} />
            <ScanMetaField label="Modules" value={activeScan.modulesCount || 0} />
          </div>

          {isFinished ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6">
              <SummaryCard label="Total vuln" value={scanSummary.total} tone="text-white" />
              <SummaryCard label="Payloads" value={sqlSummary.totalPayloads} tone="text-yellow-300" />
              <SummaryCard label="High risk" value={scanSummary.high} tone="text-red-300" />
              <SummaryCard label="Medium risk" value={scanSummary.medium} tone="text-orange-300" />
              <SummaryCard label="Low risk" value={scanSummary.low} tone="text-emerald-300" />
              <SummaryCard label="Info" value={scanSummary.info} tone="text-sky-300" />
            </div>
          ) : (
            <article className="glass-panel soft-ring rounded-2xl p-5">
              <p className="text-sm text-zinc-300">
                En attente des résultats de vulnérabilités. Les compteurs seront disponibles une fois le scan terminé.
              </p>
            </article>
          )}

          <div className="flex flex-wrap items-center justify-between gap-4 mt-8">
            <h3 className="text-lg font-semibold text-white">Vulnerabilities</h3>
            
            {isFinished ? (
              <div className="flex rounded-lg border border-zinc-800 bg-zinc-950/80 p-1">
                <button
                  type="button"
                  onClick={() => setViewMode("severity")}
                  className={`rounded-md px-4 py-1.5 text-xs font-semibold transition-all ${
                    viewMode === "severity" ? "bg-zinc-800 text-white" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  By Severity
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode("module")}
                  className={`rounded-md px-4 py-1.5 text-xs font-semibold transition-all ${
                    viewMode === "module" ? "bg-zinc-800 text-white" : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  By Module
                </button>
              </div>
            ) : null}
          </div>

          <div className="space-y-4">
            {!isFinished ? (
              <article className="glass-panel soft-ring rounded-2xl p-6">
                <p className="text-zinc-300">En attente des résultats...</p>
              </article>
            ) : !groupedVulnerabilities.length ? (
              <article className="glass-panel soft-ring rounded-2xl p-6">
                <p className="text-zinc-300">No vulnerabilities found for this scan.</p>
              </article>
            ) : (
              groupedVulnerabilities.map(([groupName, groupVulns]) => (
                <article key={groupName} className="glass-panel soft-ring rounded-2xl p-4">
                  <div className="mb-4 flex items-center justify-between border-b border-zinc-800/50 pb-3">
                    <h4 className="text-base font-semibold text-white">{groupName}</h4>
                    <span className="rounded-full border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-300">
                      {groupVulns.length} finding(s)
                    </span>
                  </div>
                  <div className="grid gap-3">
                    {groupVulns.map((vulnerability) => (
                      <GroupedVulnerabilityCard
                        key={vulnerability.id}
                        vulnerability={vulnerability}
                        onOpen={setSelectedVulnerability}
                      />
                    ))}
                  </div>
                </article>
              ))
            )}
          </div>
        </article>
      ) : null}

      <VulnerabilityDrawer isOpen={Boolean(selectedVulnerability)} onClose={() => setSelectedVulnerability(null)}>
        {selectedVulnerability ? (
          <VulnerabilityDetails vulnerability={selectedVulnerability} onBack={() => setSelectedVulnerability(null)} />
        ) : null}
      </VulnerabilityDrawer>
    </section>
  );
}
