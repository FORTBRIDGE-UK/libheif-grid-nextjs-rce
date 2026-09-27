export const metadata = {
  title: "CVE-2026-32740 Next.js research lab",
  description: "Hardcoded sharp/libheif upload and optimization lab"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "sans-serif", maxWidth: 760, margin: "40px auto" }}>
        {children}
      </body>
    </html>
  );
}
