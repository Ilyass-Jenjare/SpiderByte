import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "./AuthContext";

const ScanContext = createContext(null);

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const SCANS_KEY = "spiderbyte_scan_results";
const TERMINAL_SCAN_STATUSES = new Set(["FINISHED", "FAILURE"]);
const RUNNING_SCAN_STATUSES = new Set(["QUEUED", "PROGRESS"]);

function createId(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

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

function summarizeFindings(findings) {
  const summary = { total: findings.length, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    const severity = normalizeSeverity(finding.severity);
    summary[severity] += 1;
  });
  return summary;
}

function emptySummary() {
  return { total: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function emptySqlMetrics() {
  return { totalVulnerabilities: 0, totalPayloads: 0 };
}

function normalizeScanStatus(status) {
  const normalized = String(status || "").trim().toUpperCase();
  if (!normalized || normalized === "PENDING" || normalized === "QUEUED") {
    return "QUEUED";
  }
  if (normalized === "SUCCESS" || normalized === "FINISHED") {
    return "FINISHED";
  }
  if (normalized === "PROGRESS") {
    return "PROGRESS";
  }
  if (["FAILURE", "FAILED", "ERROR", "REVOKED"].includes(normalized)) {
    return "FAILURE";
  }
  return normalized;
}

function isFinishedScanStatus(status) {
  return normalizeScanStatus(status) === "FINISHED";
}

function isTerminalScanStatus(status) {
  return TERMINAL_SCAN_STATUSES.has(normalizeScanStatus(status));
}

function isRunningScanStatus(status) {
  return RUNNING_SCAN_STATUSES.has(normalizeScanStatus(status));
}

function normalizeProgressInfo(info) {
  if (!info || typeof info !== "object") {
    return null;
  }

  const finishedModulesRaw = info.modules_finis && typeof info.modules_finis === "object" ? info.modules_finis : {};
  const finishedModulesEntries = Object.entries(finishedModulesRaw);
  const completedModules = finishedModulesEntries.length;
  const totalToDo = Math.max(toNumber(info.total_a_faire, completedModules), completedModules);
  const lastEntry = finishedModulesEntries[finishedModulesEntries.length - 1] || null;

  return {
    statusLabel: String(info.status || ""),
    finishedModules: finishedModulesRaw,
    completedModules,
    totalToDo,
    scanType: String(info.scan_type || ""),
    elapsedTime: String(info.temps_total_ecoule || ""),
    lastModuleName: lastEntry ? String(lastEntry[0]) : "",
  };
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeSummary(summary, findings) {
  if (summary && typeof summary === "object") {
    const hasSeverityShape = ["total", "high", "medium", "low", "info"].some((key) => summary[key] !== undefined);
    if (hasSeverityShape) {
      return {
        total: toNumber(summary.total, findings.length),
        high: toNumber(summary.high),
        medium: toNumber(summary.medium),
        low: toNumber(summary.low),
        info: toNumber(summary.info),
      };
    }

    if (summary.vulnerabilities !== undefined) {
      if (findings.length > 0) {
        return summarizeFindings(findings);
      }
      return {
        total: toNumber(summary.vulnerabilities, findings.length),
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
    }
  }

  return summarizeFindings(findings);
}

function stableFindingId(scanId, module, index, suffix = "") {
  return `${scanId}-${module}-${index}${suffix ? `-${suffix}` : ""}`;
}

function normalizeSqlSeverity(vulnerability) {
  const confidence = String(vulnerability?.confidence || "").toUpperCase();
  if (confidence === "HIGH") {
    return "high";
  }
  if (confidence === "MEDIUM") {
    return "medium";
  }
  if (confidence === "LOW") {
    return "low";
  }

  const type = String(vulnerability?.type || "").toUpperCase();
  if (type.includes("AUTHENTICATION_BYPASS")) {
    return "high";
  }
  if (type.includes("ERROR")) {
    return "medium";
  }

  return "info";
}

function sqlConfidenceRank(value) {
  const confidence = String(value || "").toUpperCase();
  if (confidence === "HIGH") {
    return 3;
  }
  if (confidence === "MEDIUM") {
    return 2;
  }
  if (confidence === "LOW") {
    return 1;
  }
  return 0;
}

function normalizePayloadList(payloads, fallbackPayload = "") {
  const combined = Array.isArray(payloads) ? [...payloads] : [];
  if (fallbackPayload) {
    combined.unshift(fallbackPayload);
  }

  const seen = new Set();
  const uniquePayloads = [];
  combined.forEach((payload) => {
    const normalized = String(payload || "").trim();
    if (!normalized || seen.has(normalized)) {
      return;
    }
    seen.add(normalized);
    uniquePayloads.push(normalized);
  });

  return uniquePayloads;
}

function normalizeNmapSeverity(port) {
  const numericPort = toNumber(port, 0);
  if ([23, 3389, 3306, 5432].includes(numericPort)) {
    return "high";
  }
  if ([21, 22, 25, 445].includes(numericPort)) {
    return "medium";
  }
  if (numericPort > 0 && numericPort < 1024) {
    return "low";
  }
  return "info";
}

function findingsFromBackendResult(scan, target) {
  const backendResults = scan?.result?.results;
  if (!backendResults || typeof backendResults !== "object") {
    return [];
  }

  const scanId = String(scan.id || scan.task_id || createId("scan"));
  const findings = [];

  const sqlResult = backendResults.sql_injection;
  if (Array.isArray(sqlResult?.vulnerabilities)) {
    const sortedSqlVulnerabilities = [...sqlResult.vulnerabilities].sort((a, b) => {
      const confidenceDelta = sqlConfidenceRank(b?.confidence) - sqlConfidenceRank(a?.confidence);
      if (confidenceDelta !== 0) {
        return confidenceDelta;
      }

      const payloadDelta = toNumber(b?.count_payloads, 0) - toNumber(a?.count_payloads, 0);
      if (payloadDelta !== 0) {
        return payloadDelta;
      }

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
          endpoint,
          foundOnPage,
          payload,
          payloads,
          countPayloads,
          detectionMethod,
          type: vulnerabilityType,
          confidenceLevel,
          httpStatus: String(vulnerability?.status || ""),
          responseLength: String(vulnerability?.response_length_max || vulnerability?.response_length || ""),
          indicator,
        },
      });
    });
  }

  const nucleiResult = backendResults.nuclei_scan_copy || backendResults.nuclei_scan;
  if (Array.isArray(nucleiResult?.vulnerabilities)) {
    nucleiResult.vulnerabilities.forEach((vulnerability, index) => {
      const severity = normalizeSeverity(vulnerability?.severity);
      findings.push({
        id: stableFindingId(scanId, "nuclei", index),
        module: "nuclei",
        moduleLabel: "Nuclei",
        name: vulnerability?.name || `Nuclei finding #${index + 1}`,
        vulnerabilityType: vulnerability?.type || "TEMPLATE_MATCH",
        severity,
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

  const sslResult = backendResults.ssl_check;
  if (sslResult && typeof sslResult === "object") {
    const sslDetails = sslResult.details || {};
    const isValid = sslDetails.valid !== false;
    const daysRemaining = toNumber(sslDetails.days_remaining, 999);

    let severity = "low";
    if (!isValid) {
      severity = "high";
    } else if (daysRemaining <= 15) {
      severity = "high";
    } else if (daysRemaining <= 45) {
      severity = "medium";
    }

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
        issuer: sslDetails.issuer || "",
        subject: sslDetails.subject || "",
        tlsVersion: sslDetails.version || "",
        expiration: sslDetails.expires_on || "",
        daysRemaining: String(sslDetails.days_remaining ?? ""),
        status: isValid ? "valid" : "invalid",
      },
    });
  }

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
        description:
          missingHeaders.length > 0
            ? `${missingHeaders.length} recommended security header(s) are missing.`
            : "Potential information leak via response headers.",
        targetUrl: target,
        details: {
          missingHeaders,
          serverLeakedInfo,
        },
      });
    }
  }

  const nmapResult = backendResults.nmap_scan;
  if (Array.isArray(nmapResult?.ports)) {
    nmapResult.ports.forEach((portEntry, index) => {
      const port = String(portEntry?.port || "");
      const protocol = String(portEntry?.protocol || "tcp");
      const service = String(portEntry?.service || "unknown");
      findings.push({
        id: stableFindingId(scanId, "nmap", index),
        module: "nmap",
        moduleLabel: "Nmap",
        name: `Open port ${port}/${protocol}`,
        vulnerabilityType: "PORT_EXPOSURE",
        severity: normalizeNmapSeverity(port),
        description: `Service ${service} detected with version fingerprint.`,
        targetUrl: target,
        details: {
          port,
          protocol,
          service,
          version: String(portEntry?.version || ""),
          state: String(portEntry?.state || "open"),
        },
      });
    });
  }

  if (Array.isArray(nmapResult?.security_warnings)) {
    nmapResult.security_warnings.forEach((warning, index) => {
      findings.push({
        id: stableFindingId(scanId, "nmap-warning", index),
        module: "nmap",
        moduleLabel: "Nmap",
        name: "Exposed sensitive service",
        vulnerabilityType: "PORT_EXPOSURE",
        severity: "high",
        description: String(warning),
        targetUrl: target,
        details: {
          port: "-",
          protocol: "tcp",
          service: "sensitive-service",
          version: "-",
          state: "open",
        },
      });
    });
  }

   // XSS
  const xssResult = backendResults.xss_check;
  if (xssResult && typeof xssResult === "object") {
    const xssDetails = xssResult.details || {};
    const vulnerablePayloads = Array.isArray(xssDetails.vulnerable_payloads) ? xssDetails.vulnerable_payloads : [];
    
    vulnerablePayloads.forEach((vuln, index) => {
      findings.push({
        id: stableFindingId(scanId, "xss", index),
        module: "xss",
        moduleLabel: "XSS",
        name: "Cross-Site Scripting (XSS) detected",
        vulnerabilityType: "XSS_INJECTION",
        severity: "high",
        description: `XSS vulnerability confirmed via ${vuln.method === "input_injection" ? "input field injection" : "URL parameter injection"}.`,
        targetUrl: target,
        details: {
          payload: vuln.payload || "",
          method: vuln.method || "",
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

  const sqlFindings = findings.filter((finding) => finding.module === "sql_injection");
  const totalPayloads = sqlFindings.reduce((sum, finding) => {
    const payloadCount = toNumber(finding?.details?.countPayloads, finding?.details?.payload ? 1 : 0);
    return sum + Math.max(payloadCount, 0);
  }, 0);

  return {
    totalVulnerabilities: sqlFindings.length,
    totalPayloads,
  };
}

function normalizeLegacyVulnerability(vulnerability, scanTarget) {
  return {
    id: vulnerability.id || createId("legacy"),
    module: "legacy",
    moduleLabel: "Legacy Finding",
    name: vulnerability.title || "Legacy vulnerability",
    vulnerabilityType: String(vulnerability.severity || "info").toUpperCase(),
    severity: normalizeSeverity(vulnerability.severity),
    description: vulnerability.description || "Imported from previous scan format.",
    targetUrl: scanTarget,
    details: {
      payload: vulnerability.payload || "",
      request: vulnerability.request || "",
      response: vulnerability.response || "",
      recommendation: vulnerability.recommendation || "Review manually.",
    },
  };
}

function normalizeScan(scan) {
  const normalizedStatus = normalizeScanStatus(scan.status);
  const progress = normalizeProgressInfo(scan.progress || scan.info);
  const resultPayload = scan.result && typeof scan.result === "object" ? scan.result : null;
  const resultModules = resultPayload?.results && typeof resultPayload.results === "object" ? resultPayload.results : {};
  const target = scan.target || scan.url || resultPayload?.target || "https://example.com";

  const findingsFromScan = isFinishedScanStatus(normalizedStatus)
    ? Array.isArray(scan.findings)
      ? scan.findings.map((finding) => ({
          ...finding,
          severity: normalizeSeverity(finding.severity),
          targetUrl: finding.targetUrl || target,
        }))
      : Array.isArray(scan.vulnerabilities)
        ? scan.vulnerabilities.map((vulnerability) => normalizeLegacyVulnerability(vulnerability, target))
        : findingsFromBackendResult(scan, target)
    : [];

  const summary = isFinishedScanStatus(normalizedStatus) ? normalizeSummary(scan.summary, findingsFromScan) : emptySummary();
  const sqlMetrics = isFinishedScanStatus(normalizedStatus) ? deriveSqlMetrics(resultModules, findingsFromScan) : emptySqlMetrics();
  const modulesCount = isFinishedScanStatus(normalizedStatus)
    ? toNumber(resultPayload?.modules_count, Object.keys(resultModules).length)
    : toNumber(progress?.totalToDo, toNumber(scan.modulesCount || scan.modules_count, 0));
  const executionTime = isFinishedScanStatus(normalizedStatus)
    ? String(resultPayload?.total_execution_time || scan.executionTime || "")
    : String(progress?.elapsedTime || "");

  return {
    id: String(scan.id || createId("scan")),
    taskId: scan.taskId || scan.task_id || `task-${Date.now()}`,
    mode: scan.mode || resultPayload?.scan_type || progress?.scanType || "light",
    status: normalizedStatus,
    target,
    createdAt: scan.createdAt || scan.created_at || new Date().toISOString(),
    executionTime,
    modulesCount,
    findings: findingsFromScan,
    summary,
    sqlMetrics,
    progress,
    result: resultPayload,
  };
}

function readStoredScans() {
  if (typeof window === "undefined") {
    return [];
  }

  const raw = localStorage.getItem(SCANS_KEY);
  if (!raw) {
    return [];
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.map((scan) => normalizeScan(scan));
  } catch {
    return [];
  }
}

async function readResponsePayload(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function fetchScanDetails(scanId, token) {
  try {
    const response = await fetch(`${API_BASE_URL}/scans/${scanId}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      return null;
    }

    const payload = await readResponsePayload(response);
    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

async function fetchTaskStatus(taskId, token) {
  try {
    const response = await fetch(`${API_BASE_URL}/scan/status/${taskId}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!response.ok) {
      return null;
    }
    const payload = await readResponsePayload(response);
    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

async function fetchUserScans(token) {
  const response = await fetch(`${API_BASE_URL}/scans/history?limit=25`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error("Unable to fetch scan history.");
  }

  const payload = await readResponsePayload(response);
  const historyScans = Array.isArray(payload?.scans) ? payload.scans : [];

  const scansWithDetails = await Promise.all(
    historyScans.map(async (historyScan) => {
      if (!isFinishedScanStatus(historyScan.status)) {
        return historyScan;
      }
      const details = await fetchScanDetails(historyScan.id, token);
      if (!details) {
        return historyScan;
      }

      return {
        ...historyScan,
        ...details,
        summary: historyScan.summary,
      };
    }),
  );

  return scansWithDetails.map((scan) => normalizeScan(scan));
}

export function ScanProvider({ children }) {
  const { token, isAuthenticated } = useAuth();
  const initialScansRef = useRef(null);
  if (initialScansRef.current === null) {
    initialScansRef.current = readStoredScans();
  }

  const [scans, setScans] = useState(() => initialScansRef.current);
  const [activeScanId, setActiveScanId] = useState(() => initialScansRef.current[0]?.id || null);
  const [isLaunching, setIsLaunching] = useState(false);
  const scansRef = useRef(scans);

  useEffect(() => {
    scansRef.current = scans;
  }, [scans]);

  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem(SCANS_KEY, JSON.stringify(scans));
    }
  }, [scans]);

  useEffect(() => {
    let isActive = true;

    if (!isAuthenticated || !token) {
      setScans([]);
      setActiveScanId(null);
      return () => {
        isActive = false;
      };
    }

    async function loadBackendScans() {
      try {
        const remoteScans = await fetchUserScans(token);
        if (!isActive) {
          return;
        }
        setScans(remoteScans);
      } catch {
        // Keep local cached scans when backend is temporarily unavailable.
      }
    }

    loadBackendScans();

    return () => {
      isActive = false;
    };
  }, [isAuthenticated, token]);

  useEffect(() => {
    let isActive = true;
    let pollInFlight = false;

    async function pollRunningScans() {
      if (!isAuthenticated || !token || pollInFlight) {
        return;
      }

      const runningScans = scansRef.current.filter((scan) => scan.taskId && isRunningScanStatus(scan.status));
      if (!runningScans.length) {
        return;
      }

      pollInFlight = true;
      try {
        const statusUpdatesRaw = await Promise.all(
          runningScans.map(async (scan) => {
            const payload = await fetchTaskStatus(scan.taskId, token);
            if (!payload) {
              return null;
            }
            return {
              taskId: scan.taskId,
              status: normalizeScanStatus(payload.status),
              progress: normalizeProgressInfo(payload.info),
              result: payload.result && typeof payload.result === "object" ? payload.result : null,
            };
          }),
        );

        if (!isActive) {
          return;
        }

        const statusUpdates = new Map(
          statusUpdatesRaw.filter(Boolean).map((update) => [update.taskId, update]),
        );
        if (!statusUpdates.size) {
          return;
        }

        const shouldRefreshHistory = Array.from(statusUpdates.values()).some((update) => isTerminalScanStatus(update.status));

        const runningScanByTaskId = new Map(runningScans.map((scan) => [scan.taskId, scan]));
        const finishedScans = Array.from(statusUpdates.values())
          .filter((update) => normalizeScanStatus(update.status) === "FINISHED")
          .map((update) => runningScanByTaskId.get(update.taskId))
          .filter(Boolean);

        const finishedDetailsEntries = await Promise.all(
          finishedScans.map(async (scan) => {
            const details = await fetchScanDetails(scan.id, token);
            if (!details) {
              return null;
            }
            return [scan.taskId, details];
          }),
        );

        if (!isActive) {
          return;
        }

        const finishedDetailsByTaskId = new Map(finishedDetailsEntries.filter(Boolean));
        setScans((currentScans) =>
          currentScans.map((scan) => {
            const update = statusUpdates.get(scan.taskId);
            if (!update) {
              return scan;
            }

            const nextProgress = update.progress ?? scan.progress;
            const completedDetails = finishedDetailsByTaskId.get(scan.taskId);

            if (completedDetails && normalizeScanStatus(update.status) === "FINISHED") {
              return normalizeScan({
                ...scan,
                ...completedDetails,
                task_id: completedDetails.task_id || scan.taskId,
                created_at: completedDetails.created_at || scan.createdAt,
                url: completedDetails.url || scan.target,
                status: completedDetails.status || update.status,
                progress: nextProgress,
                result: completedDetails.result || update.result || scan.result,
              });
            }

            return normalizeScan({
              ...scan,
              task_id: scan.taskId,
              created_at: scan.createdAt,
              url: scan.target,
              status: update.status,
              progress: nextProgress,
              result: update.result || (update.status === "FINISHED" ? scan.result : null),
            });
          }),
        );

        if (shouldRefreshHistory) {
          try {
            const remoteScans = await fetchUserScans(token);
            if (isActive) {
              setScans(remoteScans);
            }
          } catch {
            // Keep optimistic in-memory state if refresh fails.
          }
        }
      } finally {
        pollInFlight = false;
      }
    }

    pollRunningScans();
    const intervalId = window.setInterval(pollRunningScans, 2500);

    return () => {
      isActive = false;
      window.clearInterval(intervalId);
    };
  }, [isAuthenticated, token]);

  useEffect(() => {
    if (!scans.length) {
      setActiveScanId(null);
      return;
    }

    const stillExists = scans.some((scan) => scan.id === activeScanId);
    if (!stillExists) {
      setActiveScanId(scans[0].id);
    }
  }, [activeScanId, scans]);

  const activeScan = useMemo(
    () => scans.find((scan) => scan.id === activeScanId) || scans[0] || null,
    [activeScanId, scans],
  );

  async function startScan({ mode, protocol, target, token: providedToken }) {
    const cleanedTarget = target.trim().replace(/^https?:\/\//i, "");
    const normalizedTarget = `${protocol}${cleanedTarget}`;
    const normalizedMode = mode === "light" ? "light" : "deep";
    const authToken = providedToken || token;
    if (!authToken) {
      throw new Error("Authentication is required to start a scan.");
    }

    setIsLaunching(true);
    try {
      const response = await fetch(`${API_BASE_URL}/scan/${normalizedMode}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ target: normalizedTarget }),
      });

      const payload = await readResponsePayload(response);
      if (!response.ok) {
        const message =
          payload && typeof payload === "object"
            ? String(payload.detail || payload.message || "Unable to start scan.")
            : "Unable to start scan.";
        throw new Error(message);
      }

      const taskId = payload && typeof payload === "object" ? payload.task_id : null;
      if (!taskId) {
        throw new Error("Scan launched but no task identifier was returned.");
      }
      const payloadObject = payload && typeof payload === "object" ? payload : {};

      const newScan = normalizeScan({
        id: payloadObject.scan_id || createId("scan"),
        task_id: taskId,
        mode: normalizedMode,
        status: payloadObject.status || "QUEUED",
        target: normalizedTarget,
        url: normalizedTarget,
        created_at: new Date().toISOString(),
        result: null,
        summary: emptySummary(),
      });

      setScans((previous) => {
        const filtered = previous.filter((scan) => scan.taskId !== newScan.taskId && scan.id !== newScan.id);
        return [newScan, ...filtered];
      });
      setActiveScanId(newScan.id);
      return newScan;
    } finally {
      setIsLaunching(false);
    }
  }

  function selectScan(scanId) {
    setActiveScanId(scanId);
  }

  const value = useMemo(
    () => ({
      scans,
      activeScan,
      activeScanId,
      isLaunching,
      startScan,
      selectScan,
    }),
    [scans, activeScan, activeScanId, isLaunching],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error("useScan must be used inside ScanProvider");
  }
  return context;
}
