export default function Home() {
  return (
    <main>
      <h1>CVE-2026-32740 Next.js research lab</h1>
      <p>
        This deliberately vulnerable, hardcoded application exposes the
        two HTTP routes used by the Fortbridge proof of concept.
      </p>
      <ul>
        <li><code>POST /api/upload</code></li>
        <li><code>GET /api/optimize?file=NAME</code></li>
      </ul>
    </main>
  );
}
