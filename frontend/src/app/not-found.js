import Link from "next/link";

export default function NotFound() {
  return (
    <main className="loading-page">
      <h1>Page not found</h1>
      <p>That link doesn&apos;t match anything in SENTINEL.</p>
      <Link className="primary-button" href="/dashboard">
        Go to dashboard
      </Link>
    </main>
  );
}
