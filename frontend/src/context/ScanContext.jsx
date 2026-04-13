import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useAuth } from "./AuthContext";

const ScanContext = createContext(null);

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const SCANS_KEY = "spiderbyte_scan_results";

function createId(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

function normalizeSeverity(value) {
  const normalized = String(value || "info").toLowerCase();
  if (normalized === "critical") return "high";
  if (normalized === "moderate") return "medium";
  if (normalized === "informational") return "info";
  if (["high", "medium", "low", "info"].includes(normalized)) return normalized;
  return "info";
}

function summarizeFindings(findings) {
  const summary = { total: findings.length, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    const severity = normalizeSeverity(finding.severity);
    summary[severity] += 1;
  });
  return summary;
}

function safeParseTarget(target) {
  try {
    const url = new URL(target);
    return { href: url.href, origin: url.origin, pathname: url.pathname || "/", host: url.host };
  } catch {
    return { href: target, origin: target, pathname: "/", host: target };
  }
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function stableFindingId(scanId, module, index, suffix = "") {
  return `${scanId}-${module}-${index}${suffix ? `-${suffix}` : ""}`;
}

function normalizeSqlSeverity(vulnerability) {
  const confidence = String(vulnerability?.confidence || "").toUpperCase();
  if (confidence === "HIGH") return "high";
  if (confidence === "MEDIUM") return "medium";
  if (confidence === "LOW") return "low";

  const type = String(vulnerability?.type || "").toUpperCase();
  if (type.includes("AUTHENTICATION_BYPASS")) return "high";
  if (type.includes("ERROR")) return "medium";

  return "info";
}

function sqlConfidenceRank(value) {
  const confidence = String(value || "").toUpperCase();
  if (confidence === "HIGH") return 3;
  if (confidence === "MEDIUM") return 2;
  if (confidence === "LOW") return 1;
  return 0;
}

function normalizePayloadList(payloads, fallbackPayload = "") {
  const combined = Array.isArray(payloads) ? [...payloads] : [];
  if (fallbackPayload) combined.unshift(fallbackPayload);

  const seen = new Set();
  const uniquePayloads = [];
  combined.forEach((payload) => {
    const normalized = String(payload || "").trim();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    uniquePayloads.push(normalized);
  });

  return uniquePayloads;
}

function normalizeNmapSeverity(port) {
  const numericPort = toNumber(port, 0);
  if ([23, 3389, 3306, 5432].includes(numericPort)) return "high";
  if ([21, 22, 25, 445].includes(numericPort)) return "medium";
  if (numericPort > 0 && numericPort < 1024) return "low";
  return "info";
}

function findingsFromBackendResult(scan, target) {
  const backendResults = scan?.result?.results || scan?.results;
  if (!backendResults || typeof backendResults !== "object") return [];

  const scanId = String(scan.id || scan.task_id || createId("scan"));
  const findings = [];

  // SQL INJECTION
  const sqlResult = backendResults.sql_injection;
  if (Array.isArray(sqlResult?.vulnerabilities)) {
    const sortedSqlVulnerabilities = [...sqlResult.vulnerabilities].sort((a, b) => {
      const confidenceDelta = sqlConfidenceRank(b?.confidence) - sqlConfidenceRank(a?.confidence);
      if (confidenceDelta !== 0) return confidenceDelta;
      const payloadDelta = toNumber(b?.count_payloads, 0) - toNumber(a?.count_payloads, 0);
      if (payloadDelta !== 0) return payloadDelta;
      const endpointA = String(a?.endpoint || a?.lien || "");
      const endpointB = String(b?.endpoint || b?.lien || "");
      return endpointA.localeCompare(endpointB);
    });

    sortedSqlVulnerabilities.forEach((vulnerability, index) => {
      const endpoint = vulnerability?.endpoint || vulnerability?.lien || target;
      const foundOnPage = vulnerability?.found_on || endpoint;
      const detectionMethod = vulnerability?.method || vulnerability?.detection_technique || "Differential analysis";
      const confidenceLevel = vulnerability?.confidence || "Unknown";
      const indicator = vulnerability?.indicator || "";
      const payloads = normalizePayloadList(vulnerability?.payloads, vulnerability?.payload);
      const payload = payloads[0] || "";
      const countPayloads = Math.max(toNumber(vulnerability?.count_payloads, payloads.length), payloads.length);
      const vulnerabilityType = vulnerability?.type || "SQLI";
      const severity = normalizeSqlSeverity(vulnerability);

      findings.push({
        id: stableFindingId(scanId, "sql", index),
        module: "sql_injection",
        moduleLabel: "SQL Injection",
        name: `${vulnerabilityType.replaceAll("_", " ")} · ${endpoint}`,
        vulnerabilityType,
        severity,
        description: indicator
          ? `Potential SQL injection discovered (${detectionMethod}) with indicator: ${indicator}. ${countPayloads} exploitable payload(s).`
          : `Potential SQL injection discovered using ${detectionMethod}. ${countPayloads} exploitable payload(s).`,
        targetUrl: endpoint,
        details: {
          endpoint, foundOnPage, payload, payloads, countPayloads, detectionMethod,
          type: vulnerabilityType, confidenceLevel,
          httpStatus: String(vulnerability?.status || ""),
          responseLength: String(vulnerability?.response_length_max || vulnerability?.response_length || ""),
          indicator,
        },
      });
    });
  }

  // NUCLEI
  const nucleiResult = backendResults.nuclei_scan_copy || backendResults.nuclei_scan;
  if (Array.isArray(nucleiResult?.vulnerabilities)) {
    nucleiResult.vulnerabilities.forEach((vulnerability, index) => {
      findings.push({
        id: stableFindingId(scanId, "nuclei", index),
        module: "nuclei",
        moduleLabel: "Nuclei",
        name: vulnerability?.name || `Nuclei finding #${index + 1}`,
        vulnerabilityType: vulnerability?.type || "TEMPLATE_MATCH",
        severity: normalizeSeverity(vulnerability?.severity),
        description: vulnerability?.description || "Template-based issue detected by Nuclei.",
        targetUrl: vulnerability?.matched_at || target,
        details: {
          name: vulnerability?.name || "",
          severity: String(vulnerability?.severity || "info").toUpperCase(),
          matchedAt: vulnerability?.matched_at || target,
          description: vulnerability?.description || "",
          tags: Array.isArray(vulnerability?.tags) ? vulnerability.tags : [],
          timestamp: vulnerability?.timestamp || "",
          cve: vulnerability?.cve || "",
          cvssScore: vulnerability?.cvss_score || "",
          remediation: vulnerability?.remediation || "",
        },
      });
    });
  }

  // SSL
  const sslResult = backendResults.ssl_check;
  if (sslResult && typeof sslResult === "object") {
    const sslDetails = sslResult.details || {};
    const isValid = sslDetails.valid !== false;
    const daysRemaining = toNumber(sslDetails.days_remaining, 999);

    let severity = "low";
    if (!isValid) severity = "high";
    else if (daysRemaining <= 15) severity = "high";
    else if (daysRemaining <= 45) severity = "medium";

    findings.push({
      id: stableFindingId(scanId, "ssl", findings.length),
      module: "ssl",
      moduleLabel: "SSL",
      name: "TLS certificate review",
      vulnerabilityType: "CERTIFICATE_ANALYSIS",
      severity,
      description: isValid
        ? `Certificate status is valid with ${daysRemaining} day(s) remaining.`
        : "Certificate validation failed or certificate is unavailable.",
      targetUrl: target,
      details: {
        issuer: sslDetails.issuer || "", subject: sslDetails.subject || "",
        tlsVersion: sslDetails.version || "", expiration: sslDetails.expires_on || "",
        daysRemaining: String(sslDetails.days_remaining ?? ""),
        status: isValid ? "valid" : "invalid",
      },
    });
  }

  // HEADERS
  const headersResult = backendResults.header_check;
  if (headersResult && typeof headersResult === "object") {
    const headerDetails = headersResult.details || {};
    const missingHeaders = Array.isArray(headerDetails.missing_headers) ? headerDetails.missing_headers : [];
    const serverLeakedInfo = headerDetails.server_leaked_info || "";

    if (missingHeaders.length > 0 || serverLeakedInfo) {
      const severity = missingHeaders.length >= 4 ? "high" : missingHeaders.length > 0 ? "medium" : "low";
      findings.push({
        id: stableFindingId(scanId, "headers", findings.length),
        module: "headers",
        moduleLabel: "Headers",
        name: "Missing hardening headers",
        vulnerabilityType: "HEADER_MISCONFIGURATION",
        severity,
        description: missingHeaders.length > 0
          ? `${missingHeaders.length} recommended security header(s) are missing.`
          : "Potential information leak via response headers.",
        targetUrl: target,
        details: { missingHeaders, serverLeakedInfo },
      });
    }
  }

  // NMAP
  const nmapResult = backendResults.nmap_scan;
  if (Array.isArray(nmapResult?.ports)) {
    nmapResult.ports.forEach((portEntry, index) => {
      const port = String(portEntry?.port || "");
      const protocol = String(portEntry?.protocol || "tcp");
      findings.push({
        id: stableFindingId(scanId, "nmap", index),
        module: "nmap",
        moduleLabel: "Nmap",
        name: `Open port ${port}/${protocol}`,
        vulnerabilityType: "PORT_EXPOSURE",
        severity: normalizeNmapSeverity(port),
        description: `Service ${portEntry?.service || "unknown"} detected with version fingerprint.`,
        targetUrl: target,
        details: {
          port, protocol, service: String(portEntry?.service || "unknown"),
          version: String(portEntry?.version || ""), state: String(portEntry?.state || "open"),
        },
      });
    });
  }

  return findings;
}

function deriveSqlMetrics(resultModules, findings) {
  const sqlResult = resultModules?.sql_injection;
  if (sqlResult && typeof sqlResult === "object") {
    const totalVulnerabilities = toNumber(sqlResult.total_vulnerabilities, toNumber(sqlResult.vulnerabilities_found, 0));
    const totalPayloads = toNumber(sqlResult.total_payloads, 0);
    if (totalVulnerabilities > 0 || totalPayloads > 0) {
      return { totalVulnerabilities, totalPayloads };
    }
  }
  const sqlFindings = findings.filter((f) => f.module === "sql_injection");
  const totalPayloads = sqlFindings.reduce((sum, f) => sum + Math.max(toNumber(f?.details?.countPayloads, f?.details?.payload ? 1 : 0), 0), 0);
  return { totalVulnerabilities: sqlFindings.length, totalPayloads };
}

function normalizeLegacyVulnerability(vulnerability, scanTarget) {
  return {
    id: vulnerability.id || createId("legacy"), module: "legacy", moduleLabel: "Legacy Finding",
    name: vulnerability.title || "Legacy vulnerability", vulnerabilityType: String(vulnerability.severity || "info").toUpperCase(),
    severity: normalizeSeverity(vulnerability.severity), description: vulnerability.description || "Imported from previous scan format.",
    targetUrl: scanTarget,
    details: { payload: vulnerability.payload || "", request: vulnerability.request || "", response: vulnerability.response || "", recommendation: vulnerability.recommendation || "Review manually." },
  };
}

function normalizeScan(scan) {
  const resultPayload = scan.result && typeof scan.result === "object" ? scan.result : null;
  const resultModules = resultPayload?.results && typeof resultPayload.results === "object" ? resultPayload.results : {};
  const target = scan.target || scan.url || resultPayload?.target || "https://example.com";
  
  const findingsFromScan = Array.isArray(scan.findings)
    ? scan.findings.map((f) => ({ ...f, severity: normalizeSeverity(f.severity), targetUrl: f.targetUrl || target }))
    : Array.isArray(scan.vulnerabilities)
      ? scan.vulnerabilities.map((v) => normalizeLegacyVulnerability(v, target))
      : findingsFromBackendResult(scan, target);

  return {
    id: String(scan.id || scan.task_id || createId("scan")),
    taskId: scan.taskId || scan.task_id || `task-${Date.now()}`,
    mode: scan.mode || "deep",
    status: scan.status || "FINISHED",
    target,
    createdAt: scan.createdAt || scan.created_at || new Date().toISOString(),
    executionTime: String(resultPayload?.total_execution_time || scan.executionTime || ""),
    modulesCount: toNumber(resultPayload?.modules_count, Object.keys(resultModules).length),
    findings: findingsFromScan,
    summary: scan.summary || summarizeFindings(findingsFromScan),
    sqlMetrics: deriveSqlMetrics(resultModules, findingsFromScan),
    progressMeta: scan.progressMeta || null
  };
}

export function ScanProvider({ children }) {
  const { token, isAuthenticated } = useAuth();
  
  const [scans, setScans] = useState(() => {
    if (typeof window === "undefined") return [];
    try {
      const raw = localStorage.getItem(SCANS_KEY);
      return raw ? JSON.parse(raw).map(normalizeScan) : [];
    } catch { return []; }
  });
  
  const [activeScanId, setActiveScanId] = useState(() => scans[0]?.id || null);
  const [isLaunching, setIsLaunching] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") localStorage.setItem(SCANS_KEY, JSON.stringify(scans));
  }, [scans]);

  // FONCTION POUR CHECKER L'API CELERY
  async function checkScanStatus(taskId) {
    if (!token) return null;
    try {
      const response = await fetch(`${API_BASE_URL}/scan/status/${taskId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.error("Erreur check statut:", error);
      return null;
    }
  }

  // CHARGEMENT INITIAL DEPUIS L'HISTORIQUE BDD
  useEffect(() => {
    let isActive = true;
    if (!isAuthenticated || !token) {
      setScans([]); setActiveScanId(null); return;
    }

    async function loadBackendScans() {
      try {
        const response = await fetch(`${API_BASE_URL}/scans/history?limit=25`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) return;
        const payload = await response.json();
        if (!isActive) return;

        const remoteScans = (payload.scans || []).map(normalizeScan);
        
        // On fusionne l'historique sans écraser les scans en attente locaux
        setScans((prev) => {
          const pendingScans = prev.filter(s => s.status === "QUEUED" || s.status === "PROGRESS");
          const remoteIds = new Set(remoteScans.map(s => s.taskId));
          const activePending = pendingScans.filter(s => !remoteIds.has(s.taskId));
          return [...activePending, ...remoteScans];
        });
      } catch (e) { console.error("Erreur historique:", e); }
    }

    loadBackendScans();
    return () => { isActive = false; };
  }, [isAuthenticated, token]);

  // POLLING EN TEMPS RÉEL
  useEffect(() => {
    const pendingScans = scans.filter(s => s.status === "QUEUED" || s.status === "PROGRESS");
    if (pendingScans.length === 0) return;

    const interval = setInterval(async () => {
      for (const scan of pendingScans) {
        const statusData = await checkScanStatus(scan.taskId);
        if (statusData) {
          setScans(prevScans => prevScans.map(s => {
            if (s.taskId === scan.taskId) {
              if (statusData.status === "PROGRESS") {
                return { ...s, status: "PROGRESS", progressMeta: statusData.meta };
              }
              if (statusData.status === "SUCCESS") {
                const backendFindings = findingsFromBackendResult({ result: statusData.result }, s.target);
                return {
                  ...s,
                  status: "FINISHED",
                  executionTime: statusData.result?.total_execution_time || "-",
                  modulesCount: statusData.result?.modules_count || 0,
                  findings: backendFindings,
                  summary: summarizeFindings(backendFindings)
                };
              }
              if (statusData.status === "FAILURE") {
                 return { ...s, status: "FAILED", executionTime: "Error" };
              }
            }
            return s;
          }));
        }
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scans, token]);

  useEffect(() => {
    if (scans.length && !scans.some(s => s.id === activeScanId)) {
      setActiveScanId(scans[0].id);
    }
  }, [activeScanId, scans]);

  const activeScan = useMemo(() => scans.find(s => s.id === activeScanId) || scans[0] || null, [activeScanId, scans]);

  async function startScan({ mode, protocol, target }) {
    setIsLaunching(true);
    const normalizedTarget = `${protocol}${target.trim().replace(/^https?:\/\//i, "")}`;
    let taskId = `task-${Date.now()}`;

    try {
      const response = await fetch(`${API_BASE_URL}/scan/${mode === "light" ? "light" : "deep"}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ target: normalizedTarget }),
      });
      if (response.ok) {
        const payload = await response.json();
        taskId = payload.task_id || taskId;
      }
    } catch {}

    const newScan = {
      id: taskId,
      taskId,
      mode: mode === "light" ? "light" : "deep",
      status: "QUEUED",
      target: normalizedTarget,
      createdAt: new Date().toISOString(),
      executionTime: "-",
      modulesCount: mode === "light" ? 3 : 6,
      findings: [],
      summary: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
      progressMeta: null
    };

    setScans((prev) => [newScan, ...prev.filter(s => s.id !== taskId)]);
    setActiveScanId(taskId);
    setIsLaunching(false);
    return newScan;
  }

  function selectScan(scanId) { setActiveScanId(scanId); }

  return (
    <ScanContext.Provider value={{ scans, activeScan, activeScanId, isLaunching, startScan, selectScan }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) throw new Error("useScan must be used inside ScanProvider");
  return context;
}