import { Route, Routes } from 'react-router-dom';
import RequireAuth from './components/RequireAuth';
import RootRedirect from './components/RootRedirect';
import Shell from './components/Shell';
import TenantLayout from './components/TenantLayout';
import AcceptInvite from './pages/AcceptInvite';
import Bootstrap from './pages/Bootstrap';
import Compare from './pages/Compare';
import Home from './pages/Home';
import Login from './pages/Login';
import NoAccess from './pages/NoAccess';
import Rules from './pages/Rules';
import SettingsPage from './pages/Settings';
import Visualizer from './pages/Visualizer';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/bootstrap" element={<Bootstrap />} />
      <Route path="/accept-invite" element={<AcceptInvite />} />

      <Route element={<RequireAuth />}>
        <Route path="/no-access" element={<NoAccess />} />
        <Route path="/" element={<RootRedirect />} />

        <Route path="/t/:tenantId" element={<TenantLayout />}>
          <Route element={<Shell />}>
            <Route index element={<Home />} />
            <Route path="rules" element={<Rules />} />
            <Route path="visualizer" element={<Visualizer />} />
            <Route path="visualizer/:productId" element={<Visualizer />} />
            <Route path="compare" element={<Compare />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Route>
      </Route>
    </Routes>
  );
}
