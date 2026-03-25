import { useNavigate } from "react-router-dom";
import HeroSection from "../components/HeroSection";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import { useToast } from "../context/ToastContext";
import { RadarIcon, ReportIcon, ServerIcon, ShieldIcon, TerminalIcon } from "../components/icons";

const featureList = [
  {
    icon: ShieldIcon,
    title: "Threat-first detection",
    description: "Detect SQLi, XSS, insecure headers and auth weaknesses with confidence scoring.",
  },
  {
    icon: RadarIcon,
    title: "Continuous reconnaissance",
    description: "Map exposed pages, forms and API routes before exploitation checks begin.",
  },
  {
    icon: ServerIcon,
    title: "Live risk monitoring",
    description: "Track your attack surface with trends and severity breakdowns in one view.",
  },
  {
    icon: ReportIcon,
    title: "Executive reporting",
    description: "Share clean summaries with leadership and detailed evidence with engineering.",
  },
  {
    icon: TerminalIcon,
    title: "Developer workflows",
    description: "Use CLI mode and automation-ready outputs for CI/CD security pipelines.",
  },
];

const reportPreviewCards = [
  {
    title: "Executive Overview",
    subtitle: "C-Level",
    detail: "Top risks, trendline and remediation velocity for leadership updates.",
  },
  {
    title: "Technical Findings",
    subtitle: "Security Team",
    detail: "Proof-of-concept payloads, request traces and actionable recommendations.",
  },
  {
    title: "Compliance Snapshot",
    subtitle: "Audit",
    detail: "Control mapping and exportable evidence for SOC2 and ISO 27001.",
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
          eyebrow="Core Capabilities"
          title="Built for modern cybersecurity teams"
          description="Cover discovery, analysis and remediation with one clean security workflow."
        />

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {featureList.map((feature) => (
            <FeatureCard key={feature.title} {...feature} />
          ))}
        </div>
      </section>

      <section id="reports" className="space-y-8">
        <SectionTitle
          eyebrow="Reports Preview"
          title="Clear visibility for technical and business stakeholders"
          description="SpiderByte combines developer detail and executive clarity in every report."
        />

        <div className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
          <article className="glass-panel soft-ring rounded-3xl p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 className="text-lg font-semibold text-white">Attack Surface Summary</h3>
              <span className="rounded-full border border-yellow-400/40 bg-yellow-400/10 px-3 py-1 text-xs text-yellow-300">
                Updated 1 min ago
              </span>
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-3">
              <ReportStat label="High" value="06" toneClass="text-red-300" />
              <ReportStat label="Medium" value="14" toneClass="text-orange-300" />
              <ReportStat label="Low" value="31" toneClass="text-emerald-300" />
            </div>

            <div className="mt-6 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4">
              <div className="mb-4 flex items-center justify-between text-sm text-zinc-400">
                <span>Weekly Risk Trend</span>
                <span>-28% unresolved high severity</span>
              </div>
              <div className="grid grid-cols-7 items-end gap-2">
                {[42, 39, 36, 30, 24, 19, 14].map((value, index) => (
                  <div
                    key={`trend-${value}-${index}`}
                    className="rounded-md bg-gradient-to-t from-yellow-500 to-yellow-300 transition-all duration-300 hover:from-yellow-400 hover:to-yellow-200"
                    style={{ height: `${value * 2}px` }}
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
