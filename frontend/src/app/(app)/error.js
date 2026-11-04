"use client";

import Link from "next/link";
import { useEffect } from "react";

export default function WorkspaceError({ error, reset }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="empty-state">
      <h3>This page hit an error</h3>
      <p>Something went wrong while showing this view. Your data is safe.</p>
      <button className="secondary-button" onClick={reset} type="button">
        Try again
      </button>
      <Link className="ghost-button" href="/dashboard">
        Back to dashboard
      </Link>
    </div>
  );
}
