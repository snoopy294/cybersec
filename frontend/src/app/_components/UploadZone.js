"use client";

import { useRef, useState } from "react";
import { MAX_UPLOAD_SIZE_BYTES, MAX_UPLOAD_SIZE_MB } from "../_lib/constants";

export default function UploadZone({ onFileSelect, disabled }) {
  const inputRef = useRef(null);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState("");

  const validateAndSubmit = (file) => {
    if (!file) {
      return;
    }

    if (file.size > MAX_UPLOAD_SIZE_BYTES) {
      setError(`File exceeds the ${MAX_UPLOAD_SIZE_MB} MB limit`);
      return;
    }

    setError("");
    onFileSelect(file);
  };

  return (
    <div
      className={`upload-zone ${dragActive ? "drag-active" : ""} ${
        disabled ? "disabled" : ""
      }`}
      onDragEnter={(event) => {
        event.preventDefault();
        setDragActive(true);
      }}
      onDragLeave={(event) => {
        event.preventDefault();
        setDragActive(false);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault();
        setDragActive(false);
        validateAndSubmit(event.dataTransfer.files?.[0]);
      }}
    >
      <input
        disabled={disabled}
        hidden
        onChange={(event) => validateAndSubmit(event.target.files?.[0])}
        ref={inputRef}
        type="file"
      />

      <div className="upload-icon">SCAN</div>
      <h3>Drop a suspicious file for analysis</h3>
      <p>
        Files are hashed, profiled, scanned for static indicators, and queued
        for the behavioral pipeline. Max size is {MAX_UPLOAD_SIZE_MB} MB.
      </p>

      <button
        className="primary-button"
        disabled={disabled}
        onClick={() => inputRef.current?.click()}
        type="button"
      >
        Choose file
      </button>

      {error ? <span className="form-error">{error}</span> : null}
    </div>
  );
}
