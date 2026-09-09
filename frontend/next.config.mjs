/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // (SEO çok-bölge slug) EN/DE yerelleştirilmiş URL alias'ları -> TR-slug route'una rewrite (afterFiles:
  // gerçek route'ları ETKİLEMEZ, yalnız eşleşmeyen /en/about gibi yolları yakalar). URL kullanıcıda kalır.
  async rewrites() {
    return {
      afterFiles: [
        { source: '/en/about', destination: '/en/hakkimizda' },
        { source: '/de/ueber-uns', destination: '/de/hakkimizda' },
        { source: '/en/contact', destination: '/en/iletisim' },
        { source: '/de/kontakt', destination: '/de/iletisim' },
        { source: '/en/open-source', destination: '/en/acik-kaynak' },
        { source: '/de/open-source', destination: '/de/acik-kaynak' },
      ],
    };
  },
  // Not: localhost'ta ve ileride cybertestify.com kok dizininde calisir;
  // alt yol (basePath) gerekmiyor.
};

export default nextConfig;