import { useState } from "react";
import { Shield, Lock, Eye, EyeOff } from "lucide-react";

const CORRECT_PASSWORD = "omowoli12345@..";
const STORAGE_KEY = "vulnscan_auth";

export function useAuth() {
  return sessionStorage.getItem(STORAGE_KEY) === "1";
}

export function PasswordGate({ children }: { children: React.ReactNode }) {
  const [authed, setAuthed]       = useState(() => sessionStorage.getItem(STORAGE_KEY) === "1");
  const [password, setPassword]   = useState("");
  const [showPw, setShowPw]       = useState(false);
  const [error, setError]         = useState("");
  const [shaking, setShaking]     = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password === CORRECT_PASSWORD) {
      sessionStorage.setItem(STORAGE_KEY, "1");
      setAuthed(true);
    } else {
      setError("Incorrect password. Access denied.");
      setShaking(true);
      setPassword("");
      setTimeout(() => setShaking(false), 600);
    }
  }

  if (authed) return <>{children}</>;

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className={`w-full max-w-sm ${shaking ? "animate-shake" : ""}`}>

        <div className="flex flex-col items-center mb-8 gap-3">
          <div className="w-16 h-16 rounded-2xl bg-sidebar-primary/10 border border-sidebar-primary/20 flex items-center justify-center">
            <Shield className="w-8 h-8 text-sidebar-primary" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-bold text-foreground tracking-tight">VulnScan Pro</h1>
            <p className="text-sm text-muted-foreground mt-1">Restricted access — authorised personnel only</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-card border border-border rounded-xl p-6 space-y-5 shadow-lg"
        >
          <div className="space-y-2">
            <label className="text-sm font-medium text-foreground flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 text-muted-foreground" />
              Access Password
            </label>
            <div className="relative">
              <input
                type={showPw ? "text" : "password"}
                value={password}
                onChange={e => { setPassword(e.target.value); setError(""); }}
                placeholder="Enter password"
                autoFocus
                className="w-full bg-background border border-border rounded-lg px-3 py-2.5 pr-10
                           text-sm text-foreground placeholder:text-muted-foreground
                           focus:outline-none focus:ring-2 focus:ring-sidebar-primary/40 focus:border-sidebar-primary/50
                           transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPw(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                tabIndex={-1}
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {error && (
              <p className="text-xs text-red-400 flex items-center gap-1">
                <span>⚠</span> {error}
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={!password}
            className="w-full bg-sidebar-primary hover:bg-sidebar-primary/90 disabled:opacity-40
                       disabled:cursor-not-allowed text-white font-medium text-sm
                       py-2.5 rounded-lg transition-colors"
          >
            Authenticate
          </button>
        </form>

        <p className="text-center text-xs text-muted-foreground mt-5">
          Unauthorized access attempts are logged.
        </p>
      </div>

      <style>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          15%       { transform: translateX(-8px); }
          30%       { transform: translateX(8px); }
          45%       { transform: translateX(-6px); }
          60%       { transform: translateX(6px); }
          75%       { transform: translateX(-3px); }
          90%       { transform: translateX(3px); }
        }
        .animate-shake { animation: shake 0.6s ease-in-out; }
      `}</style>
    </div>
  );
}
