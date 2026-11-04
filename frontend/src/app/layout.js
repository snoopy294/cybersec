import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';

// next/font downloads these at build time and serves them from this origin,
// so visitors never contact Google and the CSP can stay locked to 'self'.
const inter = Inter({ subsets: ['latin'], display: 'swap', variable: '--font-inter' });
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], display: 'swap', variable: '--font-jetbrains-mono' });

export const metadata = {
  title: 'SENTINEL — Autonomous Threat Intelligence Platform',
  description: 'We don\'t scan files. We understand them. Upload suspicious files and receive AI-powered threat analysis in under 60 seconds.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
