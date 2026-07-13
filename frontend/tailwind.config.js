/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        aegis: {
          bg: "#0b1120",
          panel: "#111827",
          border: "#1f2937",
          accent: "#38bdf8",
        },
      },
    },
  },
  plugins: [],
};
