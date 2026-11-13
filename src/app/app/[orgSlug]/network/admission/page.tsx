import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AdmissionForm } from '@/components/network/admission-form';
import { can } from '@/server/authz/roles';
import { SENSITIVITIES, ZONES } from '@/server/domain/zero-trust';
import { listDevices } from '@/server/services/devices';
import { listAssignableMembers } from '@/server/services/identities';
import { listConnectors } from '@/server/services/network';
import { loadTenantContext } from '@/server/ui/session';
import { connectorListQuerySchema, deviceListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Admission test · CyberNorf' };
export const dynamic = 'force-dynamic';

export default async function AdmissionPage({ params }: { params: Promise<{ orgSlug: string }> }) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'network.read');
  if (!ctx) {
    notFound();
  }

  const canManage = can(ctx.membership.role, 'network.manage');
  const [devices, members, connectors] = await Promise.all([
    listDevices(ctx.organization.id, deviceListQuerySchema.parse({ pageSize: 100 })),
    listAssignableMembers(ctx.organization.id),
    listConnectors(ctx.organization.id, connectorListQuerySchema.parse({ pageSize: 100 })),
  ]);
  const base = `/app/${ctx.organization.slug}`;

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/network`}>Network</Link>
          </p>
          <h1>Admission test</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Evaluates a device against the current policy and returns both the verdict and the
            network consequence: admitted, quarantined, or refused because the connector that would
            enforce it is unreachable. Every evaluation is recorded in the decision log.
          </p>
        </div>
      </div>

      <section className="card">
        <h2>Request</h2>
        {canManage ? (
          <AdmissionForm
            action={`/api/v1/organizations/${ctx.organization.slug}/network/admission`}
            zoneOptions={ZONES.map((zone) => ({ value: zone, label: zone.toLowerCase() }))}
            sensitivityOptions={SENSITIVITIES.map((value) => ({
              value,
              label: value.toLowerCase(),
            }))}
            subjectKinds={['DEVICE', 'USER', 'IDENTITY']}
            devices={devices.devices.map((device) => ({
              value: device.id,
              label: `${device.name} (${device.trustState.toLowerCase()})`,
            }))}
            members={members.map((member) => ({
              value: member.userId,
              label: `${member.name || member.email} · ${member.role}`,
            }))}
            connectors={connectors.connectors.map((connector) => ({
              value: connector.id,
              label: `${connector.name} (${connector.status.toLowerCase()})`,
            }))}
          />
        ) : (
          <p className="small muted">
            Your role can read network state but not evaluate admission. Admission persists a
            decision record, so it requires the manage capability.
          </p>
        )}
      </section>

      <section className="card" style={{ marginTop: '1.5rem' }}>
        <h2>What the answer means</h2>
        <ul className="small muted" style={{ margin: 0, paddingLeft: '1.1rem' }}>
          <li>
            <strong>allowed</strong> — policy permitted the request and the connector is reachable.
          </li>
          <li>
            <strong>allowed_degraded</strong> — permitted, but the enforcing connector is degraded.
          </li>
          <li>
            <strong>policy_denied / policy_quarantine</strong> — a rule refused or quarantined it.
          </li>
          <li>
            <strong>step_up_required</strong> — an obligation such as a second factor must be met
            first.
          </li>
          <li>
            <strong>connector_unreachable_fail_closed</strong> — policy allowed it, but the
            connector could not enforce it and is configured to deny on failure.
          </li>
        </ul>
      </section>
    </>
  );
}
