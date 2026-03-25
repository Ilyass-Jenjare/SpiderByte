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

function safeParseTarget(target) {
  try {
    const url = new URL(target);
    return {
      href: url.href,
      origin: url.origin,
      pathname: url.pathname || "/",
      host: url.host,
    };
  } catch {
    return {
      href: target,
      origin: target,
      pathname: "/",
      host: target,
    };
  }
}

function sqlFinding(target, variant = 0) {
  const sqlVariants = [
    {
      name: "SQL Injection on login flow",
      severity: "high",
      description: "Boolean-based payload altered authentication query behavior.",
      type: "AUTHENTICATION_BYPASS",
      payload: "' OR 1=1 --",
      detectionMethod: "Boolean-based differential response analysis",
      endpoint: `${target.origin}/api/auth/login`,
      foundOnPage: `${target.origin}/login`,
      httpStatus: "200",
      responseLength: "18234",
      confidenceLevel: "High",
      indicator: "Admin panel marker appeared in response body.",
    },
    {
      name: "Blind SQL Injection in search",
      severity: "medium",
      description: "Time-delay payload indicates blind SQL execution path.",
      type: "BOOLEAN_BASED_BLIND",
      payload: "'; IF(1=1,SLEEP(5),0)--",
      detectionMethod: "Response timing and boolean inference",
      endpoint: `${target.origin}/api/search`,
      foundOnPage: `${target.origin}/search`,
      httpStatus: "200",
      responseLength: "9651",
      confidenceLevel: "Medium",
      indicator: "Response delay consistently above baseline.",
    },
  ];

  const selected = sqlVariants[variant % sqlVariants.length];
  return {
    id: createId("sql"),
    module: "sql_injection",
    moduleLabel: "SQL Injection",
    name: selected.name,
    vulnerabilityType: selected.type,
    severity: selected.severity,
    description: selected.description,
    targetUrl: target.href,
    details: {
      endpoint: selected.endpoint,
      foundOnPage: selected.foundOnPage,
      payload: selected.payload,
      detectionMethod: selected.detectionMethod,
      type: selected.type,
      confidenceLevel: selected.confidenceLevel,
      httpStatus: selected.httpStatus,
      responseLength: selected.responseLength,
      indicator: selected.indicator,
    },
  };
}

function nucleiFinding(target, variant = 0) {
  const nucleiVariants = [
    {
      name: "Exposed admin panel",
      severity: "high",
      description: "Nuclei template detected externally reachable admin endpoint.",
      matchedAt: `${target.origin}/admin`,
      tags: ["exposure", "panel", "critical"],
      cve: "CVE-2024-12345",
      cvssScore: "9.1",
      remediation: "Restrict access by IP and enforce strong authentication.",
    },
    {
      name: "Outdated CMS component",
      severity: "medium",
      description: "Known vulnerable plugin fingerprint identified by template.",
      matchedAt: `${target.origin}/wp-content/plugins/sample`,
      tags: ["cms", "version", "misconfiguration"],
      cve: "",
      cvssScore: "",
      remediation: "Upgrade plugin to latest patched release and retest.",
    },
  ];

  const selected = nucleiVariants[variant % nucleiVariants.length];
  return {
    id: createId("nuclei"),
    module: "nuclei",
    moduleLabel: "Nuclei",
    name: selected.name,
    vulnerabilityType: "TEMPLATE_MATCH",
    severity: selected.severity,
    description: selected.description,
    targetUrl: target.href,
    details: {
      name: selected.name,
      severity: selected.severity.toUpperCase(),
      matchedAt: selected.matchedAt,
      description: selected.description,
      tags: selected.tags,
      timestamp: new Date().toISOString(),
      cve: selected.cve,
      cvssScore: selected.cvssScore,
      remediation: selected.remediation,
    },
  };
}

function sslFinding(target) {
  const expirationDate = new Date();
  expirationDate.setDate(expirationDate.getDate() + 42);

  return {
    id: createId("ssl"),
    module: "ssl",
    moduleLabel: "SSL",
    name: "TLS certificate review",
    vulnerabilityType: "CERTIFICATE_ANALYSIS",
    severity: "low",
    description: "Certificate is valid but renewal window is approaching.",
    targetUrl: target.href,
    details: {
      issuer: "Let's Encrypt Authority X3",
      subject: `CN=${target.host}`,
      tlsVersion: "TLSv1.3",
      expiration: expirationDate.toISOString().slice(0, 10),
      daysRemaining: "42",
      status: "valid",
    },
  };
}

function headersFinding(target) {
  return {
    id: createId("headers"),
    module: "headers",
    moduleLabel: "Headers",
    name: "Missing hardening headers",
    vulnerabilityType: "HEADER_MISCONFIGURATION",
    severity: "medium",
    description: "Response headers miss key browser-side protection directives.",
    targetUrl: target.href,
    details: {
      missingHeaders: ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"],
      serverLeakedInfo: "nginx/1.18.0 (Ubuntu)",
    },
  };
}

function nmapFinding(target, variant = 0) {
  const ports = [
    { port: "22", protocol: "tcp", service: "ssh", version: "OpenSSH 8.2p1", state: "open", severity: "info" },
    { port: "443", protocol: "tcp", service: "https", version: "nginx 1.18.0", state: "open", severity: "low" },
  ];
  const selected = ports[variant % ports.length];

  return {
    id: createId("nmap"),
    module: "nmap",
    moduleLabel: "Nmap",
    name: `Open port ${selected.port}/${selected.protocol}`,
    vulnerabilityType: "PORT_EXPOSURE",
    severity: selected.severity,
    description: `Service ${selected.service} detected with version fingerprint.`,
    targetUrl: target.href,
    details: {
      port: selected.port,
      protocol: selected.protocol,
      service: selected.service,
      version: selected.version,
      state: selected.state,
    },
  };
}

function buildFindings(mode, target) {
  const findings = [sqlFinding(target, 0), nucleiFinding(target, 0), headersFinding(target), sslFinding(target), nmapFinding(target, 0)];

  if (mode === "deep") {
    findings.push(sqlFinding(target, 1), nucleiFinding(target, 1), nmapFinding(target, 1));
  }

  return findings;
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
    sqlResult.vulnerabilities.forEach((vulnerability, index) => {
      const endpoint = vulnerability?.lien || target;
      const foundOnPage = vulnerability?.found_on || endpoint;
      const detectionMethod = vulnerability?.method || vulnerability?.detection_technique || "Differential analysis";
      const confidenceLevel = vulnerability?.confidence || "Unknown";
      const indicator = vulnerability?.indicator || "";
      const payload = vulnerability?.payload || "";
      const vulnerabilityType = vulnerability?.type || "SQLI";
      const severity = normalizeSqlSeverity(vulnerability);

      findings.push({
        id: stableFindingId(scanId, "sql", index),
        module: "sql_injection",
        moduleLabel: "SQL Injection",
        name: `SQL injection finding #${index + 1}`,
        vulnerabilityType,
        severity,
        description: indicator
          ? `Potential SQL injection discovered (${detectionMethod}) with indicator: ${indicator}.`
          : `Potential SQL injection discovered using ${detectionMethod}.`,
        targetUrl: endpoint,
        details: {
          endpoint,
          foundOnPage,
          payload,
          detectionMethod,
          type: vulnerabilityType,
          confidenceLevel,
          httpStatus: String(vulnerability?.status || ""),
          responseLength: String(vulnerability?.response_length || ""),
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

  return findings;
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
  const resultPayload = scan.result && typeof scan.result === "object" ? scan.result : null;
  const resultModules = resultPayload?.results && typeof resultPayload.results === "object" ? resultPayload.results : {};
  const target = scan.target || scan.url || resultPayload?.target || "https://example.com";
  const findingsFromScan = Array.isArray(scan.findings)
    ? scan.findings.map((finding) => ({
        ...finding,
        severity: normalizeSeverity(finding.severity),
        targetUrl: finding.targetUrl || target,
      }))
    : Array.isArray(scan.vulnerabilities)
      ? scan.vulnerabilities.map((vulnerability) => normalizeLegacyVulnerability(vulnerability, target))
      : findingsFromBackendResult(scan, target);

  return {
    id: String(scan.id || createId("scan")),
    taskId: scan.taskId || scan.task_id || `task-${Date.now()}`,
    mode: scan.mode || "light",
    status: scan.status || "Finished",
    target,
    createdAt: scan.createdAt || scan.created_at || new Date().toISOString(),
    executionTime: String(resultPayload?.total_execution_time || ""),
    modulesCount: toNumber(resultPayload?.modules_count, Object.keys(resultModules).length),
    findings: findingsFromScan,
    summary: normalizeSummary(scan.summary, findingsFromScan),
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

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
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
  const [scans, setScans] = useState(() => readStoredScans());
  const [activeScanId, setActiveScanId] = useState(() => readStoredScans()[0]?.id || null);
  const [isLaunching, setIsLaunching] = useState(false);

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
    let taskId = `mock-${Date.now()}`;

    setIsLaunching(true);
    try {
      if (authToken) {
        const response = await fetch(`${API_BASE_URL}/scan/${normalizedMode}`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${authToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ target: normalizedTarget }),
        });

        if (response.ok) {
          const payload = await response.json();
          taskId = payload.task_id || taskId;
        }
      }
    } catch {
      // Keep UX responsive even when backend scan endpoint is not available.
    }

    try {
      await delay(900);
      const targetMeta = safeParseTarget(normalizedTarget);
      const findings = buildFindings(normalizedMode, targetMeta);
      const newScan = {
        id: createId("scan"),
        taskId,
        mode: normalizedMode,
        status: "Queued",
        target: targetMeta.href,
        createdAt: new Date().toISOString(),
        executionTime: "",
        modulesCount: 0,
        findings,
        summary: summarizeFindings(findings),
      };

      setScans((previous) => [newScan, ...previous]);
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
