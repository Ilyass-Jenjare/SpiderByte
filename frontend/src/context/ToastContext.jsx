import { createContext, useContext, useMemo, useState } from "react";

const ToastContext = createContext(null);

function randomId() {
  return `${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  function removeToast(id) {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }

  function showToast(message, type = "info", duration = 3200) {
    const id = randomId();
    setToasts((current) => [...current, { id, message, type }]);

    setTimeout(() => {
      removeToast(id);
    }, duration);
  }

  const value = useMemo(
    () => ({
      toasts,
      showToast,
      removeToast,
    }),
    [toasts],
  );

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used inside ToastProvider");
  }
  return context;
}

const toneMap = {
  success: "border-emerald-400/50 bg-emerald-500/10 text-emerald-200",
  error: "border-red-400/50 bg-red-500/10 text-red-200",
  warning: "border-yellow-400/50 bg-yellow-500/10 text-yellow-200",
  info: "border-zinc-600 bg-zinc-800/80 text-zinc-100",
};

export function ToastViewport() {
  const { toasts, removeToast } = useToast();

  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-[60] flex w-[min(360px,92vw)] flex-col gap-3">
      {toasts.map((toast) => (
        <article
          key={toast.id}
          className={`pointer-events-auto rounded-xl border px-4 py-3 text-sm shadow-xl transition duration-300 ${toneMap[toast.type] || toneMap.info}`}
        >
          <div className="flex items-start justify-between gap-3">
            <p className="leading-relaxed">{toast.message}</p>
            <button
              type="button"
              className="text-xs uppercase tracking-wide opacity-80 transition hover:opacity-100"
              onClick={() => removeToast(toast.id)}
            >
              Close
            </button>
          </div>
        </article>
      ))}
    </div>
  );
}
