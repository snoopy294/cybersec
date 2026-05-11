/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Enable standalone output for production Docker deployments
  output: process.env.NODE_ENV === 'production' ? 'standalone' : undefined,

  async rewrites() {
    // In production, the reverse proxy (Nginx/Caddy) handles routing.
    // In development, proxy API calls to the local backend.
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl.replace(/\/$/, '')}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
