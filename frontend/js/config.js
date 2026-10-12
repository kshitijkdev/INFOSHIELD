/**
 * InfoShield — Frontend Runtime Environment Configuration
 * 
 * Instructions for Online Deployment:
 * 1. For local development, this defaults to 'http://127.0.0.1:8000'.
 * 2. When your backend is live on Render:
 *    - Enter your Render backend URL below in BACKEND_URL (e.g. 'https://infoshield-backend.onrender.com').
 *    - OR you can instantly override it from any mobile phone or laptop browser
 *      by appending '?backend=https://your-render-url.onrender.com' to the page URL!
 *    - OR leave BACKEND_URL as "" to use same-origin Vercel reverse proxy (/api/...).
 */
window.INFOSHIELD_CONFIG = {
  // Set your hosted Render backend URL here once deployed:
  // e.g. "https://infoshield-backend.onrender.com"
      BACKEND_URL: "http://127.0.0.1:8000"

};
