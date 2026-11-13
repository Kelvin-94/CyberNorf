import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { listFlows } from '@/server/services/network';
import { loadTenantContext } from '@/server/ui/session';
import { flowListQuerySchema } from '@/server/validation/zero-trust';

export const metadata: Metadata = { title: 'Flows · CyberNorf' };
export const dynamic = 'force-dynamic';

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = value / 1024;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${units[unit]}`;
}

function endpoint(address: string, port: number | null): string {
  return port === null ? address : `${address}:${port}`;
}

export default async function FlowsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgSlug: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgSlug } = await params;
  const ctx = await loadTenantContext(orgSlug, 'network.read');
  if (!ctx) {
    notFound();
  }

  const raw = await searchParams;
  const parsed = flowListQuerySchema.safeParse({
    page: raw.page,
    pageSize: raw.pageSize,
    sourceAddress: raw.sourceAddress,
    destinationAddress: raw.destinationAddress,
    protocol: raw.protocol,
  });
  const query = parsed.success ? parsed.data : flowListQuerySchema.parse({});
  const invalidFilter = parsed.success ? null : parsed.error.issues[0]?.message;

  const { flows, page } = await listFlows(ctx.organization.id, query);
  const base = `/app/${ctx.organization.slug}`;

  const filterParams = new URLSearchParams();
  for (const [key, value] of Object.entries({
    sourceAddress: query.sourceAddress,
    destinationAddress: query.destinationAddress,
    protocol: query.protocol,
    pageSize: String(query.pageSize),
  })) {
    if (value) {
      filterParams.set(key, value);
    }
  }
  const pageHref = (target: number) => {
    const next = new URLSearchParams(filterParams);
    next.set('page', String(target));
    return `${base}/network/flows?${next.toString()}`;
  };

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">
            <Link href={`${base}/network`}>Network</Link>
          </p>
          <h1>Flows</h1>
          <p className="small muted" style={{ marginTop: '0.35rem' }}>
            Connection summaries reported by connectors. The control plane stores metadata only —
            addressing, ports, protocol, byte counts and timing — never payloads. Flow records feed
            the lateral-movement and egress detections.
          </p>
        </div>
      </div>

      {invalidFilter ? (
        <p className="banner warning" role="status">
          Filter ignored: {invalidFilter}
        </p>
      ) : null}

      <section className="card">
        <div className="row" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <h2>Observed flows</h2>
          <form method="get" className="row" style={{ gap: '0.4rem', flexWrap: 'wrap' }}>
            <input
              name="sourceAddress"
              defaultValue={query.sourceAddress ?? ''}
              placeholder="Source IPv4"
              aria-label="Source address"
              style={{ width: '11rem' }}
            />
            <input
              name="destinationAddress"
              defaultValue={query.destinationAddress ?? ''}
              placeholder="Destination IPv4"
              aria-label="Destination address"
              style={{ width: '11rem' }}
            />
            <input
              name="protocol"
              defaultValue={query.protocol ?? ''}
              placeholder="Protocol"
              aria-label="Protocol"
              style={{ width: '7rem' }}
            />
            <button type="submit" className="secondary">
              Filter
            </button>
          </form>
        </div>

        {flows.length === 0 ? (
          <p className="small muted" style={{ marginTop: '1rem' }}>
            No flows recorded for this filter. Connectors post summaries to the ingest endpoint;
            nothing appears here until a connector reports traffic.
          </p>
        ) : (
          <table className="data-table" style={{ marginTop: '1rem' }}>
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Bytes</th>
                <th>Observed</th>
              </tr>
            </thead>
            <tbody>
              {flows.map((flow) => (
                <tr key={flow.id}>
                  <td className="mono small">{endpoint(flow.sourceAddress, flow.sourcePort)}</td>
                  <td className="mono small">
                    {endpoint(flow.destinationAddress, flow.destinationPort)}
                  </td>
                  <td className="small">{flow.protocol}</td>
                  <td className="small">{formatBytes(flow.bytes)}</td>
                  <td className="small">{new Date(flow.observedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="row" style={{ justifyContent: 'space-between', marginTop: '1rem' }}>
          <p className="small muted" style={{ margin: 0 }}>
            {page.total} flow{page.total === 1 ? '' : 's'} · page {page.page} of {page.pageCount}
          </p>
          <div className="row" style={{ gap: '0.4rem' }}>
            {page.page > 1 ? (
              <Link className="nav-link" href={pageHref(page.page - 1)}>
                Previous
              </Link>
            ) : null}
            {page.page < page.pageCount ? (
              <Link className="nav-link" href={pageHref(page.page + 1)}>
                Next
              </Link>
            ) : null}
          </div>
        </div>
      </section>
    </>
  );
}
