import { useAlertsSocket } from "./hooks/useAlertsSocket";
import AlertFeed from "./components/AlertFeed";
import NetworkGraph from "./components/NetworkGraph";
import AlertDetail from "./components/AlertDetail";

export default function App() {
  const {
    alerts,
    connectionState,
    lastError,
    selectedAlertId,
    setSelectedAlertId,
  } = useAlertsSocket();

  const selectedAlert = alerts.find((a) => a.alert_id === selectedAlertId) ?? null;

  return (
    <main className="flex h-screen flex-col bg-slate-900 text-slate-100">
      {/* Top bar */}
      <header className="flex items-center gap-3 border-b border-slate-700 px-6 py-3">
        <h1 className="text-xl font-bold">AegisNet</h1>
        <span className="text-sm text-slate-400">Intrusion Detection Dashboard</span>
      </header>

      {/* Main content: left feed + right detail/graph */}
      <div className="flex min-h-0 flex-1">
        {/* Left column — Alert Feed (full height, scrollable) */}
        <div className="w-[420px] shrink-0 border-r border-slate-700">
          <AlertFeed
            alerts={alerts}
            connectionState={connectionState}
            lastError={lastError}
            selectedAlertId={selectedAlertId}
            onSelectAlert={setSelectedAlertId}
          />
        </div>

        {/* Right column — Network Graph / Alert Detail */}
        <div className="flex min-w-0 flex-1 flex-col">
          {selectedAlert ? (
            <AlertDetail alert={selectedAlert} onClose={() => setSelectedAlertId(null)} />
          ) : (
            <NetworkGraph />
          )}
        </div>
      </div>
    </main>
  );
}
