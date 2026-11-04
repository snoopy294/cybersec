"use client";

// Last-resort boundary for errors in the root layout itself.
export default function GlobalError({ reset }) {
  return (
    <html lang="en">
      <body>
        <main className="loading-page">
          <h1>SENTINEL is having trouble loading</h1>
          <p>Refresh the page, or try again in a minute.</p>
          <button className="primary-button" onClick={reset} type="button">
            Try again
          </button>
        </main>
      </body>
    </html>
  );
}
