/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Enable standalone output for production Docker deployments
  output: process.env.NODE_ENV === 'production' ? 'standalone' : undefined,

  async rewrites() {
    // Proxy API calls to the backend (Render in production, localhost in development).
    const backendUrl = process.env.BACKEND_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl.replace(/\/$/, '')}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
