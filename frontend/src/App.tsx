import AlertDetail from "./components/AlertDetail";
import AlertFeed from "./components/AlertFeed";
import NetworkGraph from "./components/NetworkGraph";
import ShapExplanationPanel from "./components/ShapExplanationPanel";

export default function App() {
  return (
    <main className="min-h-screen bg-slate-900 p-8 text-slate-100">
      <h1 className="mb-2 text-2xl font-bold">AegisNet Dashboard</h1>
      <p className="mb-6 text-slate-400">
        Phase 1 placeholder — live components arrive in Phase 6.
      </p>
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <AlertFeed />
        <NetworkGraph />
        <AlertDetail />
        <ShapExplanationPanel />
      </div>
    </main>
  );
}