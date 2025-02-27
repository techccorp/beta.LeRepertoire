/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.{html,htm,jinja,jinja2}",
    "./static/src/**/*.{js,jsx,ts,tsx}",
    "./app.py",
    "./routes/**/*.py",
    "./**/*.html"  // Safety check for any HTML files in project root
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#1d4ed8',
          light: '#3b82f6',
          dark: '#1e40af'
        },
        secondary: {
          DEFAULT: '#db2777',
          light: '#ec4899',
          dark: '#be185d'
        }
      },
      screens: {
        'xs': '375px',
        '3xl': '1920px'
      },
      fontFamily: {
        'sans': ['Inter var', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace']
      }
    },
    container: {
      center: true,
      padding: {
        DEFAULT: '1rem',
        sm: '2rem',
        lg: '4rem'
      }
    }
  },
  plugins: [
    require('@tailwindcss/typography'),
    require('@tailwindcss/forms'),
    require('@tailwindcss/aspect-ratio')
  ],
  darkMode: 'class',  // Enable class-based dark mode
  corePlugins: {
    float: false,      // Disable float utilities
    clear: false       // Disable clear utilities
  }
}
