/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        canvas: '#07111f',
        panel: '#0c1828',
        cyan: '#39e6ff'
      }
    }
  },
  plugins: []
}
