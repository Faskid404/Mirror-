import { Switch, Route, Router as WouterRouter, Link, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Dashboard    from "@/pages/Dashboard";
import CVEScanner   from "@/pages/CVEScanner";
import AttackChains from "@/pages/AttackChains";
import Reports      from "@/pages/Reports";
import NotFound     from "@/pages/not-found";
import {
  LayoutDashboard, Shield, Link2, FileText,
  Terminal, ChevronRight,
} from "lucide-react";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
});

const NAV = [
  { href: "/",        label: "Dashboard",      icon: LayoutDashboard },
  { href: "/cves",    label: "CVE Scanner",    icon: Shield },
  { href: "/chains",  label: "Attack Chains",  icon: Link2 },
  { href: "/reports", label: "Reports",        icon: FileText },
];

function Sidebar() {
  const [loc] = useLocation();
  return (
    <aside className="w-56 shrink-0 border-r border-border bg-sidebar flex flex-col">
      <div className="px-4 py-5 border-b border-sidebar-border">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded bg-primary/20 border border-primary/40 flex items-center justify-center">
            <Terminal className="w-4 h-4 text-primary" />
          </div>
          <div>
            <p className="text-sm font-semibold text-sidebar-foreground leading-none">VulnScan</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">Pro Arsenal v3.0</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-2 space-y-0.5">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? loc === "/" : loc.startsWith(href);
          return (
            <Link key={href} href={href}>
              <a className={`flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors
                ${active
                  ? "bg-sidebar-primary/15 text-sidebar-primary border border-sidebar-primary/20"
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                }`}>
                <Icon className="w-4 h-4 shrink-0" />
                {label}
                {active && <ChevronRight className="w-3 h-3 ml-auto" />}
              </a>
            </Link>
          );
        })}
      </nav>

      <div className="p-3 border-t border-sidebar-border">
        <div className="text-[10px] text-muted-foreground space-y-0.5">
          <p>197 HTTP probes</p>
          <p>146 CVEs covered</p>
          <p>6 attack chains</p>
          <p>70 platforms</p>
        </div>
      </div>
    </aside>
  );
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">{children}</main>
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
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}
