/** @type {import('next').NextConfig} */
const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    // Same-origin proxy so the browser never needs the API origin/CORS.
    // /api/* is the application API; /docs, /redoc and /openapi.json expose the
    // backend's interactive API reference through the frontend origin, so the
    // footer link works everywhere and never points at localhost in production.
    return [
      { source: "/api/:path*", destination: `${backendUrl}/api/:path*` },
      { source: "/docs", destination: `${backendUrl}/docs` },
      { source: "/redoc", destination: `${backendUrl}/redoc` },
      { source: "/openapi.json", destination: `${backendUrl}/openapi.json` },
    ];
  },
};

export default nextConfig;
