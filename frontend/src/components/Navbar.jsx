import { useEffect, useRef, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { ChevronDownIcon, SpiderIcon, UserCircleIcon } from "./icons";

function menuLinkClass({ isActive }) {
  const base =
    "relative text-sm text-zinc-300 transition duration-300 hover:text-yellow-300 after:absolute after:-bottom-1 after:left-0 after:h-[1px] after:w-full after:origin-left after:scale-x-0 after:bg-yellow-300 after:transition after:duration-300 hover:after:scale-x-100";
  return isActive ? `${base} text-yellow-300 after:scale-x-100` : base;
}

function buttonLinkClass({ isActive }) {
  return `rounded-xl border px-4 py-2 text-sm font-medium transition duration-300 ${
    isActive
      ? "border-yellow-400 bg-yellow-400 text-black"
      : "border-zinc-700 text-zinc-200 hover:border-zinc-500 hover:bg-zinc-900"
  }`;
}

function getInitials(username) {
  if (!username) {
    return "SB";
  }
  const normalized = String(username).trim();
  if (!normalized) {
    return "SB";
  }
  return normalized.slice(0, 2).toUpperCase();
}

export default function Navbar() {
  const { isAuthenticated, user, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    function onClickOutside(event) {
      if (!dropdownRef.current || dropdownRef.current.contains(event.target)) {
        return;
      }
      setIsOpen(false);
    }

    document.addEventListener("mousedown", onClickOutside);
    return () => {
      document.removeEventListener("mousedown", onClickOutside);
    };
  }, []);

  function handleLogout() {
    logout();
    setIsOpen(false);
    navigate("/login");
  }

  return (
    <header className="soft-ring glass-panel flex flex-wrap items-center justify-between gap-4 px-5 py-4">
      <Link to="/" className="group inline-flex items-center gap-3">
        <span className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-yellow-400 text-black shadow-[0_8px_24px_rgba(250,204,21,0.35)] transition-transform duration-300 group-hover:scale-105">
          <SpiderIcon className="h-5 w-5" />
        </span>
        <span className="text-lg font-semibold tracking-wide text-zinc-100">SpiderByte</span>
      </Link>

      <nav className="hidden items-center gap-7 md:flex">
        <NavLink to="/" className={menuLinkClass}>
          Scanner
        </NavLink>
        <a href="/#features" className="relative text-sm text-zinc-300 transition duration-300 hover:text-yellow-300">
          Features
        </a>
        <a href="/#reports" className="relative text-sm text-zinc-300 transition duration-300 hover:text-yellow-300">
          Reports
        </a>
      </nav>

      {!isAuthenticated ? (
        <div className="flex items-center gap-3">
          <NavLink to="/login" className={buttonLinkClass}>
            Login
          </NavLink>
          <NavLink to="/signup" className="accent-button text-sm">
            Sign Up
          </NavLink>
        </div>
      ) : (
        <div ref={dropdownRef} className="relative">
          <button
            type="button"
            className="flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900/80 px-3 py-2 text-sm text-zinc-100 transition duration-300 hover:border-zinc-500"
            onClick={() => setIsOpen((current) => !current)}
          >
            <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-yellow-400/90 text-xs font-semibold text-black">
              {getInitials(user?.username)}
            </span>
            <span className="max-w-[9rem] truncate">{user?.username || "Account"}</span>
            <ChevronDownIcon className={`h-4 w-4 transition duration-300 ${isOpen ? "rotate-180" : ""}`} />
          </button>

          {isOpen ? (
            <div className="absolute right-0 z-30 mt-2 w-44 rounded-xl border border-zinc-700 bg-zinc-900 p-2 shadow-2xl">
              <button
                type="button"
                className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm text-zinc-200 transition duration-300 hover:bg-zinc-800"
                onClick={() => {
                  setIsOpen(false);
                  navigate("/dashboard");
                }}
              >
                <UserCircleIcon className="h-4 w-4" />
                Dashboard
              </button>
              <button
                type="button"
                className="mt-1 w-full rounded-lg px-3 py-2 text-left text-sm text-zinc-200 transition duration-300 hover:bg-zinc-800"
                onClick={handleLogout}
              >
                Logout
              </button>
            </div>
          ) : null}
        </div>
      )}
    </header>
  );
}
