import { useState } from "react";
  import { Switch, Route, Router as WouterRouter, Link, useLocation } from "wouter";
  import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
  import { Toaster } from "@/components/ui/toaster";
  import { TooltipProvider } from "@/components/ui/tooltip";
  import { PasswordGate } from "@/components/PasswordGate";
  import Dashboard    from "@/pages/Dashboard";
  import CVEScanner   from "@/pages/CVEScanner";
  import AttackChains from "@/pages/AttackChains";
  import Reports      from "@/pages/Reports";
  import NotFound     from "@/pages/not-found";
  import {
    LayoutDashboard, Shield, Link2, FileText,
    Terminal, ChevronRight, Menu, X,
  } from "lucide-react";

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
  });

  const NAV = [
    { href: "/",        label: "Dashboard",     icon: LayoutDashboard },
    { href: "/cves",    label: "CVE Scanner",   icon: Shield },
    { href: "/chains",  label: "Attack Chains", icon: Link2 },
    { href: "/reports", label: "Reports",       icon: FileText },
  ];

  function Sidebar({ onClose }: { onClose?: () => void }) {
    const [loc] = useLocation();
    return (
      <aside className="w-64 md:w-56 h-full bg-sidebar border-r border-border flex flex-col">
        <div className="px-4 py-5 border-b border-sidebar-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-primary/20 border border-primary/40 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-primary" />
            </div>
            <div>
              <p className="text-sm font-semibold text-sidebar-foreground leading-none">VulnScan</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">Pro Arsenal v3.0</p>
            </div>
          </div>
          {onClose && (
            <button onClick={onClose} className="md:hidden p-1 rounded text-muted-foreground hover:text-foreground">
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        <nav className="flex-1 p-2 space-y-0.5">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? loc === "/" : loc.startsWith(href);
            return (
              <Link key={href} href={href} onClick={onClose}
                className={`flex items-center gap-2.5 px-3 py-2.5 rounded-md text-sm transition-colors
                  ${active
                    ? "bg-sidebar-primary/15 text-sidebar-primary border border-sidebar-primary/20"
                    : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                  }`}>
                <Icon className="w-4 h-4 shrink-0" />
                {label}
                {active && <ChevronRight className="w-3 h-3 ml-auto" />}
              </Link>
            );
          })}
        </nav>

        <div className="p-3 border-t border-sidebar-border">
          <div className="text-[10px] text-muted-foreground space-y-0.5">
            <p>18 modules (14 recon + 4 exploit)</p>
            <p>197 HTTP probes</p>
            <p>146 CVEs covered</p>
            <p>6 attack chains</p>
          </div>
        </div>
      </aside>
    );
  }

  function Layout({ children }: { children: React.ReactNode }) {
    const [open, setOpen] = useState(false);
    return (
      <div className="flex h-screen overflow-hidden bg-background">
        {open && (
          <div className="fixed inset-0 z-40 bg-black/60 md:hidden" onClick={() => setOpen(false)} />
        )}
        <div className={`fixed inset-y-0 left-0 z-50 flex flex-col transition-transform duration-200
          ${open ? "translate-x-0" : "-translate-x-full"}
          md:relative md:translate-x-0 md:z-auto`}>
          <Sidebar onClose={() => setOpen(false)} />
        </div>
        <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
          <header className="md:hidden flex items-center gap-3 px-4 py-3 border-b border-border bg-sidebar shrink-0">
            <button onClick={() => setOpen(true)} className="p-1 text-muted-foreground hover:text-foreground">
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-primary/20 border border-primary/40 flex items-center justify-center">
                <Terminal className="w-3.5 h-3.5 text-primary" />
              </div>
              <span className="text-sm font-semibold text-sidebar-foreground">VulnScan Pro</span>
            </div>
          </header>
          <main className="flex-1 overflow-y-auto">{children}</main>
        </div>
      </div>
    );
  }

  function Router() {
    return (
      <Layout>
        <Switch>
          <Route path="/"        component={Dashboard} />
          <Route path="/cves"    component={CVEScanner} />
          <Route path="/chains"  component={AttackChains} />
          <Route path="/reports" component={Reports} />
          <Route component={NotFound} />
        </Switch>
      </Layout>
    );
  }

  export default function App() {
    return (
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <PasswordGate>
            <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
              <Router />
            </WouterRouter>
            <Toaster />
          </PasswordGate>
        </TooltipProvider>
      </QueryClientProvider>
    );
  }
  