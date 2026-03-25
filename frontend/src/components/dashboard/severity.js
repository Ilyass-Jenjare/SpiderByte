const severityToneMap = {
  high: {
    badge: "border-red-400/50 bg-red-500/20 text-red-200",
    subtle: "text-red-300",
  },
  medium: {
    badge: "border-orange-400/50 bg-orange-500/20 text-orange-200",
    subtle: "text-orange-300",
  },
  low: {
    badge: "border-emerald-400/50 bg-emerald-500/20 text-emerald-200",
    subtle: "text-emerald-300",
  },
  info: {
    badge: "border-sky-400/50 bg-sky-500/20 text-sky-200",
    subtle: "text-sky-300",
  },
};

export function normalizeSeverity(value) {
  const normalized = String(value || "info").trim().toLowerCase();
  if (normalized === "critical") {
    return "high";
  }
  if (normalized === "moderate") {
    return "medium";
  }
  if (normalized === "informational") {
    return "info";
  }
  return severityToneMap[normalized] ? normalized : "info";
}

export function getSeverityTone(value) {
  return severityToneMap[normalizeSeverity(value)];
}
