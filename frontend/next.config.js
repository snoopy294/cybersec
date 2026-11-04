/** @type {import('next').NextConfig} */

const isDev = process.env.NODE_ENV !== 'production';

// Next.js inlines its bootstrap scripts, so script-src needs 'unsafe-inline'
// without a nonce setup. The rest is locked to this origin; the browser only
// talks to /api, which the rewrite below proxies to the backend.
const contentSecurityPolicy = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const securityHeaders = [
  { key: 'Content-Security-Policy', value: contentSecurityPolicy },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
];

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  // Enable standalone output for production Docker deployments
  output: process.env.NODE_ENV === 'production' ? 'standalone' : undefined,

  experimental: {
    // The /api proxy truncates request bodies past this size (10MB by default).
    // Uploads are capped at 10MB (MAX_UPLOAD_SIZE_MB); this leaves room for
    // multipart framing so the backend can answer with a proper 413.
    middlewareClientMaxBodySize: '12mb',
  },

  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },

  async rewrites() {
    // Proxy API calls to the backend (Render in production, localhost in development).
    const backendUrl = (process.env.BACKEND_URL || 'http://localhost:8000').trim();
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl.replace(/\/$/, '')}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
