import Image from 'next/image';
import Link from 'next/link';

const metrics = [
  { label: 'Static signals', value: '5K+' },
  { label: 'Report views', value: '6' },
  { label: 'Workflow', value: 'Upload to verdict' },
];

const useCases = [
  'SOC triage intake',
  'Malware research notes',
  'Incident response evidence',
  'Detection rule drafting',
];

export default function LandingPage() {
  return (
    <main className="marketing-page">
      <section className="marketing-hero">
        <Image
          src="/sentinel-hero.png"
          alt="SENTINEL threat intelligence dashboard preview"
          fill
          priority
          sizes="100vw"
          className="marketing-hero-image"
        />
        <div className="marketing-hero-shade" />
        <nav className="marketing-nav">
          <Link href="/" className="marketing-brand" aria-label="SENTINEL home">
            <span className="marketing-brand-mark">S</span>
            <span>SENTINEL</span>
          </Link>
          <div className="marketing-nav-actions">
            <Link href="/dashboard" className="marketing-nav-link">Dashboard</Link>
            <Link href="/dashboard" className="btn btn-primary">Open App</Link>
          </div>
        </nav>
        <div className="marketing-hero-content">
          <p className="marketing-kicker">Autonomous threat intelligence</p>
          <h1>SENTINEL</h1>
          <p className="marketing-hero-copy">
            Upload suspicious files, extract static evidence, and turn noisy malware signals into a living analyst report.
          </p>
          <div className="marketing-actions">
            <Link href="/dashboard" className="btn btn-primary">Analyze a File</Link>
            <a href="#workflow" className="btn btn-ghost">View Workflow</a>
          </div>
        </div>
      </section>

      <section className="marketing-band">
        <div className="marketing-inner">
          <div className="marketing-metrics" aria-label="SENTINEL product signals">
            {metrics.map((item) => (
              <div className="marketing-metric" key={item.label}>
                <span>{item.value}</span>
                <p>{item.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="marketing-section" id="workflow">
        <div className="marketing-inner marketing-two-column">
          <div>
            <p className="marketing-kicker">From sample to report</p>
            <h2>Built for fast analyst judgment.</h2>
            <p>
              SENTINEL keeps the workflow direct: ingest a file, compute hashes, extract strings and IOCs,
              map suspicious behavior, then preserve the result as a searchable report.
            </p>
          </div>
          <div className="marketing-workflow">
            <div>
              <span>01</span>
              <strong>Ingest</strong>
              <p>Upload a sample and capture immutable hashes.</p>
            </div>
            <div>
              <span>02</span>
              <strong>Reason</strong>
              <p>Score static signals with benign installer context.</p>
            </div>
            <div>
              <span>03</span>
              <strong>Act</strong>
              <p>Review IOCs, behavior matches, and draft detections.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="marketing-section marketing-section-muted">
        <div className="marketing-inner">
          <div className="marketing-section-header">
            <p className="marketing-kicker">Use cases</p>
            <h2>For teams that need signal without ceremony.</h2>
          </div>
          <div className="marketing-use-cases">
            {useCases.map((item) => (
              <div className="marketing-use-case" key={item}>{item}</div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
