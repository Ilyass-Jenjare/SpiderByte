import ScanCard from "./ScanCard";

function MetricPill({ label, value }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 px-4 py-3 transition duration-300 hover:border-zinc-700">
      <p className="text-xs uppercase tracking-[0.16em] text-zinc-500">{label}</p>
      <p className="mt-2 text-lg font-semibold text-zinc-100">{value}</p>
    </div>
  );
}

export default function HeroSection({ onStartScan, isLaunching }) {
  return (
    <section className="grid items-start gap-8 lg:grid-cols-[1.08fr_0.92fr]">
      <div className="space-y-7">
        <span className="inline-flex items-center rounded-full border border-yellow-400/40 bg-yellow-400/10 px-4 py-1 text-xs uppercase tracking-[0.24em] text-yellow-300">
          Academic Cybersecurity Project
        </span>

        <div className="space-y-4">
          <h1 className="text-balance text-4xl font-semibold leading-tight text-white md:text-6xl">
            Advanced Web Vulnerability Scanner
          </h1>
          <p className="max-w-2xl text-base leading-relaxed text-zinc-300 md:text-lg">
            Detect SQL injections, exposed ports, weak HTTP headers, and SSL misconfigurations. 
            SpiderByte utilizes asynchronous workers to deliver deep reconnaissance without slowing you down.
          </p>
        </div>

        {/* VRAIES INFORMATIONS TECHNIQUES AU LIEU DES FAUSSES STATS */}
        <div className="grid gap-4 text-sm text-zinc-300 sm:grid-cols-3">
          <MetricPill label="Scan Engines" value="Nuclei & Nmap" />
          <MetricPill label="Custom Scripts" value="SQL Injection" />
          <MetricPill label="Architecture" value="Celery Workers" />
        </div>
      </div>

      <ScanCard onStartScan={onStartScan} isLaunching={isLaunching} />
    </section>
  );
}