import { useMemo, useState } from "react";
import { SpinnerIcon } from "./icons";

const scanModes = [
  { id: "light", label: "Light Scan", note: "Fast baseline checks" },
  { id: "deep", label: "Deep Scan", note: "Extended crawl + exploit tests" },
];

const protocolOptions = ["https://", "http://"];

function ModeTab({ active, label, onClick }) {
  return (
    <button
      type="button"
      className={`rounded-xl px-3 py-2 text-xs font-semibold transition duration-300 ${
        active
          ? "bg-yellow-400 text-black shadow-[0_8px_24px_rgba(250,204,21,0.35)]"
          : "bg-zinc-900 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
      }`}
      onClick={onClick}
    >
      {label}
    </button>
  );
}

export default function ScanCard({ onStartScan, isLaunching }) {
  const [activeMode, setActiveMode] = useState(scanModes[0].id);
  const [protocol, setProtocol] = useState(protocolOptions[0]);
  const [targetInput, setTargetInput] = useState("");
  const [feedback, setFeedback] = useState("");

  const activeModeData = useMemo(
    () => scanModes.find((mode) => mode.id === activeMode) || scanModes[0],
    [activeMode],
  );

  const fullTarget = useMemo(() => {
    const cleaned = targetInput.trim().replace(/^https?:\/\//i, "");
    return cleaned ? `${protocol}${cleaned}` : "";
  }, [protocol, targetInput]);

  async function handleSubmit(event) {
    event.preventDefault();

    if (!targetInput.trim()) {
      setFeedback("Please enter a valid target URL.");
      return;
    }

    setFeedback("");
    try {
      const successMessage = await onStartScan({
        mode: activeMode,
        protocol,
        target: targetInput,
      });

      if (successMessage) {
        setFeedback(successMessage);
      }
    } catch {
      setFeedback("Unable to start scan right now.");
    }
  }

  return (
    <div className="glass-panel soft-ring rounded-3xl p-6">
      <div className="mb-5 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Scan Console</h2>
        <span className="rounded-full border border-zinc-700 bg-zinc-900/70 px-3 py-1 text-xs text-zinc-300">
          {activeModeData.note}
        </span>
      </div>

      <div className="mb-5 grid grid-cols-2 gap-2 rounded-2xl border border-zinc-800 bg-zinc-950/80 p-2">
        {scanModes.map((mode) => (
          <ModeTab key={mode.id} active={mode.id === activeMode} label={mode.label} onClick={() => setActiveMode(mode.id)} />
        ))}
      </div>

      <form className="space-y-4" onSubmit={handleSubmit}>
        <div>
          <label className="mb-2 block text-sm text-zinc-300" htmlFor="target-url">
            Target URL
          </label>
          <input
            id="target-url"
            className="input-dark"
            placeholder="example.com"
            value={targetInput}
            onChange={(event) => setTargetInput(event.target.value)}
          />
        </div>

        <div>
          <label className="mb-2 block text-sm text-zinc-300" htmlFor="protocol-select">
            Protocol
          </label>
          <select
            id="protocol-select"
            className="input-dark"
            value={protocol}
            onChange={(event) => setProtocol(event.target.value)}
          >
            {protocolOptions.map((option) => (
              <option key={option} value={option}>
                {option.toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        <button type="submit" className="accent-button flex w-full items-center justify-center gap-2 py-3 text-sm" disabled={isLaunching}>
          {isLaunching ? <SpinnerIcon className="h-4 w-4 animate-spin" /> : null}
          {isLaunching ? "Scanning..." : "Start Scan"}
        </button>
      </form>

      <div className="mt-4 rounded-xl border border-zinc-800 bg-zinc-900/70 px-4 py-3 text-sm text-zinc-300 transition duration-300">
        {feedback || "Run a scan to preview findings in your secure dashboard."}
      </div>

      {fullTarget ? (
        <p className="mt-3 font-mono text-xs text-zinc-500">
          Next target: <span className="text-zinc-300">{fullTarget}</span>
        </p>
      ) : null}
    </div>
  );
}
