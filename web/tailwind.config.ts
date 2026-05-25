import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#0b1020",
        surface: "#111827",
        accent: "#22d3ee",
        accent2: "#f59e0b",
        muted: "#94a3b8"
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"]
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,211,238,0.2), 0 20px 60px rgba(15,23,42,0.4)"
      },
      backgroundImage: {
        mesh:
          "radial-gradient(60% 60% at 20% 10%, rgba(34,211,238,0.15), transparent 60%), radial-gradient(50% 50% at 80% 0%, rgba(245,158,11,0.15), transparent 60%), radial-gradient(80% 60% at 50% 100%, rgba(56,189,248,0.1), transparent 70%)"
      }
    }
  },
  plugins: []
};

export default config;
