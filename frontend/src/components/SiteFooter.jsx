// src/components/SiteFooter.jsx
export default function SiteFooter() {
  return (
    <footer className="mt-20 border-t border-zinc-800 pt-8">
      <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-lg font-semibold text-white">SpiderByte</p>
          <p className="text-sm text-zinc-400">Threat visibility for every release cycle.</p>
        </div>

        <div className="flex flex-wrap gap-5 text-sm text-zinc-400">
          <a href="#" className="transition hover:text-yellow-300">Privacy</a>
          <a href="#" className="transition hover:text-yellow-300">Terms</a>
          <a href="#" className="transition hover:text-yellow-300">Status</a>
          <a href="#" className="transition hover:text-yellow-300">Contact</a>
        </div>
      </div>
    </footer>
  );
}