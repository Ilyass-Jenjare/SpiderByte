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

function normalizeSeverity(value) {
  const normalized = String(value || "info").toLowerCase();
  if (normalized === "critical") {
    return "high";
  }
  if (normalized === "moderate") {
    return "medium";
  }
  if (normalized === "informational") {
    return "info";
  }
  if (["high", "medium", "low", "info"].includes(normalized)) {
    return normalized;
  }
  return "info";
}

function severityBadgeTone(severity) {
  if (severity === "high") {
    return "border-red-400/50 bg-red-500/20 text-red-200";
  }
  if (severity === "medium") {
    return "border-orange-400/50 bg-orange-500/20 text-orange-200";
  }
  if (severity === "low") {
    return "border-emerald-400/50 bg-emerald-500/20 text-emerald-200";
  }
  return "border-sky-400/50 bg-sky-500/20 text-sky-200";
}

function formatDateTime(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return date.toLocaleString();
}

function formatStatus(status) {
  const normalized = String(status || "unknown").trim();
  return normalized ? normalized.toUpperCase() : "UNKNOWN";
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
    if (summary[severity] !== undefined) {
      summary[severity] += 1;
    } else {
      summary.info += 1;
    }
  });
  return summary;
}

function normalizeSummary(summary, vulnerabilities) {
  const fallback = summarizeFromFindings(vulnerabilities);
  if (!summary || typeof summary !== "object") {
    return fallback;
  }

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
        <p>
          <span className="text-zinc-500">Date:</span> {formatDateTime(scan.createdAt)}
        </p>
        <p>
          <span className="text-zinc-500">Total vulnerabilities:</span> {summary.total}
        </p>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <span className="rounded-full border border-red-400/40 bg-red-500/10 px-3 py-1 text-xs text-red-200">HIGH {summary.high}</span>
        <span className="rounded-full border border-orange-400/40 bg-orange-500/10 px-3 py-1 text-xs text-orange-200">
          MEDIUM {summary.medium}
        </span>
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

  return (
    <button
      type="button"
      className="w-full rounded-xl border border-zinc-800 bg-zinc-950/70 p-4 text-left transition duration-300 hover:border-zinc-600 hover:bg-zinc-900"
      onClick={() => onOpen(vulnerability)}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h4 className="text-sm font-semibold text-white">{vulnerability.name || "Vulnerability"}</h4>
        <span className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${badgeTone}`}>{severity}</span>
      </div>
      <p className="mt-2 text-xs uppercase tracking-wide text-zinc-500">{vulnerability.vulnerabilityType || "General"}</p>
      <p className="mt-2 text-sm text-zinc-300">{vulnerability.description || "No description."}</p>
      <p className="mt-3 truncate font-mono text-xs text-zinc-400">{vulnerability.targetUrl || "-"}</p>
    </button>
  );
}

export default function Dashboard() {
  const { scans, activeScan, activeScanId, selectScan } = useScan();
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);

  const vulnerabilities = useMemo(() => {
    if (!activeScan) {
      return [];
    }
    if (Array.isArray(activeScan.findings)) {
      return activeScan.findings;
    }
    if (Array.isArray(activeScan.vulnerabilities)) {
      return activeScan.vulnerabilities.map((item) => normalizeLegacyToFinding(item, activeScan.target || activeScan.url || "-"));
    }
    return [];
  }, [activeScan]);

  const scanSummary = useMemo(() => normalizeSummary(activeScan?.summary, vulnerabilities), [activeScan?.summary, vulnerabilities]);

  const groupedVulnerabilities = useMemo(() => {
    const groups = new Map();
    vulnerabilities.forEach((vulnerability) => {
      const key = vulnerability.module || "legacy";
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key).push(vulnerability);
    });

    const ordered = [];
    MODULE_ORDER.forEach((key) => {
      if (groups.has(key)) {
        ordered.push([key, groups.get(key)]);
        groups.delete(key);
      }
    });

    groups.forEach((value, key) => {
      ordered.push([key, value]);
    });

    return ordered;
  }, [vulnerabilities]);

  useEffect(() => {
    setSelectedVulnerability(null);
  }, [activeScan?.id]);

  if (!scans.length) {
    return (
      <section className="space-y-6">
        <h1 className="text-3xl font-semibold text-white">Reports Dashboard</h1>
        <article className="glass-panel soft-ring rounded-2xl p-6">
          <p className="text-zinc-300">No scan results yet. Launch your first scan from the landing page.</p>
          <Link to="/" className="accent-button mt-4 inline-flex">
            Go to Scanner
          </Link>
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
            <ScanCard
              key={scan.id}
              scan={scan}
              isActive={scan.id === activeScanId}
              onSelect={() => selectScan(scan.id)}
            />
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

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <SummaryCard label="Total vulnerabilities" value={scanSummary.total} tone="text-white" />
            <SummaryCard label="High risk" value={scanSummary.high} tone="text-red-300" />
            <SummaryCard label="Medium risk" value={scanSummary.medium} tone="text-orange-300" />
            <SummaryCard label="Low risk" value={scanSummary.low} tone="text-emerald-300" />
            <SummaryCard label="Info" value={scanSummary.info} tone="text-sky-300" />
          </div>

          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-white">Vulnerabilities by type</h3>
            {!groupedVulnerabilities.length ? (
              <article className="glass-panel soft-ring rounded-2xl p-6">
                <p className="text-zinc-300">No vulnerabilities found for this scan.</p>
              </article>
            ) : (
              groupedVulnerabilities.map(([module, moduleVulnerabilities]) => (
                <article key={module} className="glass-panel soft-ring rounded-2xl p-4">
                  <div className="mb-4 flex items-center justify-between">
                    <h4 className="text-base font-semibold text-white">{MODULE_LABELS[module] || module}</h4>
                    <span className="rounded-full border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-300">
                      {moduleVulnerabilities.length} item(s)
                    </span>
                  </div>
                  <div className="grid gap-3">
                    {moduleVulnerabilities.map((vulnerability) => (
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
