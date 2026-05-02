import './globals.css';

export const metadata = {
  title: 'SENTINEL — Autonomous Threat Intelligence Platform',
  description: 'We don\'t scan files. We understand them. Upload suspicious files and receive AI-powered threat analysis in under 60 seconds.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
