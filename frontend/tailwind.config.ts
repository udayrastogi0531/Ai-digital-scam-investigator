import type { Config } from "tailwindcss";

export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          950: "#04070d",
          925: "#060a12",
          900: "#080d18",
          875: "#0a1020",
          850: "#0d1426",
          800: "#111a30",
          750: "#16203a",
          700: "#1c2847",
          600: "#2b3a63",
          500: "#41538a",
        },
        accent: "#22d3ee",
        accent2: "#38bdf8",
        violet: "#818cf8",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        "glow-accent": "0 0 24px rgba(34, 211, 238, 0.16)",
        "glow-accent-sm": "0 0 12px rgba(34, 211, 238, 0.22)",
        "glow-red": "0 0 24px rgba(248, 113, 113, 0.18)",
        card: "0 1px 0 0 rgba(148, 163, 184, 0.06) inset, 0 8px 24px -12px rgba(0, 0, 0, 0.5)",
        "card-hover": "0 0 0 1px rgba(34, 211, 238, 0.22), 0 12px 32px -12px rgba(0, 0, 0, 0.6)",
      },
      backgroundImage: {
        "grid-faint":
          "linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)",
        "radial-top":
          "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(34,211,238,0.09), transparent 60%)",
        "radial-left":
          "radial-gradient(ellipse 60% 40% at 0% 30%, rgba(56,189,248,0.06), transparent 60%)",
        "radial-right":
          "radial-gradient(ellipse 60% 40% at 100% 30%, rgba(129,140,248,0.05), transparent 60%)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "scale-in": {
          "0%": { opacity: "0", transform: "scale(0.96)" },
          "100%": { opacity: "1", transform: "scale(1)" },
        },
        "pulse-dot": {
          "0%, 100%": { opacity: "1", boxShadow: "0 0 0 0 rgba(52,211,153,0.45)" },
          "50%": { opacity: "0.7", boxShadow: "0 0 0 5px rgba(52,211,153,0)" },
        },
        "pulse-dot-amber": {
          "0%, 100%": { opacity: "1", boxShadow: "0 0 0 0 rgba(251,191,36,0.45)" },
          "50%": { opacity: "0.7", boxShadow: "0 0 0 5px rgba(251,191,36,0)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-400px 0" },
          "100%": { backgroundPosition: "400px 0" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
        "flow-x": {
          "0%": { strokeDashoffset: "24" },
          "100%": { strokeDashoffset: "0" },
        },
        "grid-drift": {
          "0%": { backgroundPosition: "0 0, 0 0" },
          "100%": { backgroundPosition: "0 40px, 40px 0" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)", opacity: "0" },
          "15%": { opacity: "1" },
          "85%": { opacity: "1" },
          "100%": { transform: "translateY(400%)", opacity: "0" },
        },
        "bar-grow": {
          "0%": { transform: "scaleX(0)", opacity: "0.4" },
          "100%": { transform: "scaleX(1)", opacity: "1" },
        },
        "spin-slow": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
      animation: {
        "fade-up": "fade-up 0.5s ease-out both",
        "fade-in": "fade-in 0.4s ease-out both",
        "scale-in": "scale-in 0.25s ease-out both",
        "pulse-dot": "pulse-dot 2s ease-in-out infinite",
        "pulse-dot-amber": "pulse-dot-amber 2s ease-in-out infinite",
        shimmer: "shimmer 1.6s linear infinite",
        float: "float 6s ease-in-out infinite",
        "flow-x": "flow-x 1.4s linear infinite",
        "grid-drift": "grid-drift 20s linear infinite",
        "scan-line": "scan-line 2.6s ease-in-out infinite",
        "bar-grow": "bar-grow 0.7s cubic-bezier(0.22, 1, 0.36, 1) both",
        "spin-slow": "spin-slow 14s linear infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;