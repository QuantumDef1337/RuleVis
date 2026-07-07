import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';

export default function TenantSwitcher() {
  const { tenantId } = useParams();
  const { tenants } = useAuth();
  const navigate = useNavigate();

  if (tenants.length <= 1) {
    return tenants[0] ? <div className="tenant-badge">{tenants[0].name}</div> : null;
  }

  return (
    <select
      className="tenant-switcher"
      value={tenantId ?? ''}
      onChange={e => navigate(`/t/${e.target.value}`)}
    >
      {tenants.map(t => (
        <option key={t.id} value={t.id}>{t.name}</option>
      ))}
    </select>
  );
}
