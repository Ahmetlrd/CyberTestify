import type { Config } from 'tailwindcss';

/**
 * CyberTestify tasarim sistemi.
 * Palet (brief): derin teal (guven+kontrol) + sicak amber CTA + off-white zemin.
 * Rakiplerin mavi/mor/siyahindan bilincli olarak ayrisir.
 */
const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#123F3A', // ana teal
          dark: '#0E3B36',
          deep: '#0A2E2A',
          600: '#14514A',
          500: '#1C6B60',
          300: '#5FA396',
          100: '#DCEAE6',
          50: '#EEF5F3',
        },
        accent: {
          DEFAULT: '#F5A623', // amber CTA
          hover: '#FF9F43',
          600: '#E0940E',
          soft: '#FDECC8',
        },
        ink: {
          DEFAULT: '#111827',
          soft: '#374151',
          muted: '#6B7280',
        },
        canvas: '#FAFAF7', // off-white ana zemin (saf beyaz degil)
        surface: '#FFFFFF',
        line: '#E7E5DF',
      },
      fontFamily: {
        sans: ['var(--font-jakarta)', 'system-ui', 'sans-serif'],
      },
      borderRadius: {
        card: '12px',
        pill: '999px',
      },
      boxShadow: {
        card: '0 1px 2px rgba(17,24,39,0.04), 0 8px 24px rgba(17,24,39,0.06)',
        glow: '0 0 0 1px rgba(95,163,150,0.35), 0 8px 30px rgba(18,63,58,0.18)',
      },
      maxWidth: {
        content: '1120px',
      },
      keyframes: {
        'fade-up': { '0%': { opacity: '0', transform: 'translateY(12px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        pulseRing: { '0%': { boxShadow: '0 0 0 0 rgba(245,166,35,0.5)' }, '70%': { boxShadow: '0 0 0 10px rgba(245,166,35,0)' }, '100%': { boxShadow: '0 0 0 0 rgba(245,166,35,0)' } },
      },
      animation: {
        'fade-up': 'fade-up 0.6s ease-out both',
        'pulse-ring': 'pulseRing 2s infinite',
      },
    },
  },
  plugins: [],
};

export default config;
