import { useNavigate } from "react-router-dom";
import HeroSection from "../components/HeroSection";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import { useToast } from "../context/ToastContext";
import { RadarIcon, ReportIcon, ServerIcon, ShieldIcon, TerminalIcon } from "../components/icons";

// LISTE MISE À JOUR AVEC TES VRAIS MODULES
const featureList = [
  {
    icon: ShieldIcon,
    title: "SQL Injection Detection",
    description: "Custom payloads to identify boolean-based and error-based SQL vulnerabilities on target endpoints.",
  },
  {
    icon: RadarIcon,
    title: "Nuclei Integration",
    description: "Template-based scanning to discover known CVEs, misconfigurations, and exposed admin panels.",
  },
  {
    icon: ServerIcon,
    title: "Port Reconnaissance (Nmap)",
    description: "Scans for open ports and identifies underlying services to map the external attack surface.",
  },
  {
    icon: ReportIcon,
    title: "Security Posture Check",
    description: "Analyzes SSL/TLS certificate validity and verifies the presence of strict HTTP security headers.",
  },
  {
    icon: TerminalIcon,
    title: "Asynchronous Execution",
    description: "Powered by Redis and Celery to process heavy background scans without freezing the interface.",
  },
];

const reportPreviewCards = [
  {
    title: "Vulnerability Details",
    subtitle: "Evidence",
    detail: "View the exact payloads used to trigger the vulnerability and the server's response.",
  },
  {
    title: "Remediation Guidance",
    subtitle: "Fix",
    detail: "Actionable steps to patch SQL injections and properly configure security headers.",
  },
  {
    title: "Severity Breakdown",
    subtitle: "Triage",
    detail: "Findings are categorized from INFO to HIGH to prioritize the patching process.",
  },
];

function SectionTitle({ eyebrow, title, description }) {
  return (
    <div className="space-y-3">
      <p className="text-xs uppercase tracking-[0.22em] text-yellow-300/90">{eyebrow}</p>
      <h2 className="max-w-3xl text-3xl font-semibold text-white md:text-4xl">{title}</h2>
      <p className="max-w-2xl text-zinc-300">{description}</p>
    </div>
  );
}

function FeatureCard({ icon: Icon, title, description }) {
  return (
    <article className="glass-panel soft-ring group rounded-2xl p-5 transition duration-300 hover:-translate-y-1 hover:border-yellow-400/40">
      <span className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl bg-yellow-400/15 text-yellow-300 transition duration-300 group-hover:bg-yellow-400 group-hover:text-black">
        <Icon className="h-5 w-5" />
      </span>
      <h3 className="text-base font-semibold text-white">{title}</h3>
      <p className="mt-2 text-sm leading-relaxed text-zinc-300">{description}</p>
    </article>
  );
}

function ReportPreviewCard({ card }) {
  return (
    <article className="glass-panel soft-ring rounded-2xl p-5 transition duration-300 hover:-translate-y-1 hover:border-yellow-400/40">
      <span className="inline-flex rounded-full border border-zinc-700 px-3 py-1 text-xs text-zinc-300">{card.subtitle}</span>
      <h3 className="mt-4 text-base font-semibold text-white">{card.title}</h3>
      <p className="mt-2 text-sm text-zinc-300">{card.detail}</p>
    </article>
  );
}

function ReportStat({ label, value, toneClass }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</p>
      <p className={`mt-2 text-2xl font-semibold ${toneClass}`}>{value}</p>
    </div>
  );
}

export default function LandingPage() {
  const navigate = useNavigate();
  const { isAuthenticated, token } = useAuth();
  const { startScan, isLaunching } = useScan();
  const { showToast } = useToast();

  async function handleStartScan({ mode, protocol, target }) {
    if (!isAuthenticated) {
      showToast("Login is required before launching a scan.", "warning");
      navigate("/login", { state: { from: "scan" } });
      return "Redirecting to login...";
    }

    try {
      const scan = await startScan({ mode, protocol, target, token });
      showToast(`Scan started for ${scan.target}`, "success");
      navigate("/dashboard");
      return `Scan queued: ${scan.taskId}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Scan failed to start.";
      showToast(message, "error");
      return message;
    }
  }

  return (
    <div className="space-y-20">
      <HeroSection onStartScan={handleStartScan} isLaunching={isLaunching} />

      <section id="features" className="space-y-8">
        <SectionTitle
          eyebrow="Under the hood"
          title="Modular Scanning Architecture"
          description="SpiderByte combines the best open-source tools with custom Python scripts."
        />

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {featureList.map((feature) => (
            <FeatureCard key={feature.title} {...feature} />
          ))}
        </div>
      </section>

      <section id="reports" className="space-y-8">
        <SectionTitle
          eyebrow="Dashboard Preview"
          title="Clear visibility on vulnerabilities"
          description="A centralized view to analyze findings and extract proof-of-concept payloads."
        />

        <div className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
          <article className="glass-panel soft-ring rounded-3xl p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 className="text-lg font-semibold text-white">Example Scan Result</h3>
              <span className="rounded-full border border-yellow-400/40 bg-yellow-400/10 px-3 py-1 text-xs text-yellow-300">
                demo.testfire.net
              </span>
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-3">
              <ReportStat label="High Risk" value="02" toneClass="text-red-300" />
              <ReportStat label="Medium Risk" value="05" toneClass="text-orange-300" />
              <ReportStat label="Low / Info" value="12" toneClass="text-emerald-300" />
            </div>

            <div className="mt-6 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4">
              <div className="mb-4 flex items-center justify-between text-sm text-zinc-400">
                <span>Scan Progress Simulation</span>
                <span>100% Complete</span>
              </div>
              <div className="grid grid-cols-7 items-end gap-2">
                {/* Graphique simulé plus réaliste */}
                {[10, 15, 25, 40, 60, 80, 100].map((value, index) => (
                  <div
                    key={`trend-${value}-${index}`}
                    className="rounded-md bg-gradient-to-t from-yellow-500 to-yellow-300 transition-all duration-300 hover:from-yellow-400 hover:to-yellow-200"
                    style={{ height: `${value}px` }}
                  />
                ))}
              </div>
            </div>
          </article>

          <aside className="space-y-4">
            {reportPreviewCards.map((card) => (
              <ReportPreviewCard key={card.title} card={card} />
            ))}
          </aside>
        </div>
      </section>
    </div>
  );
}