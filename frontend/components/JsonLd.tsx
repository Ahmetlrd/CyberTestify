// Yapisal veri (JSON-LD) enjekte eder. Server component — <head>/<body> icine
// <script type="application/ld+json"> basar. Icerik guvenilir (bizim urettigimiz obje).
export function JsonLd({ data }: { data: Record<string, unknown> }) {
  return (
    <script
      type="application/ld+json"
      // JSON.stringify guvenli; '<' kacislari XSS'i onler (script-ici </script> kirilmasin).
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\\u003c') }}
    />
  );
}
