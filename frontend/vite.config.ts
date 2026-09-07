import { defineConfig, Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import localtunnel from 'localtunnel';

function tunnelPlugin(): Plugin {
  return {
    name: 'auto-tunnel',
    configureServer(server) {
      if (process.env.TUNNEL === 'true') {
        server.httpServer?.once('listening', async () => {
          try {
            const tunnel = await localtunnel({ port: 3000 });
            console.log(`\n  \x1b[1m\x1b[32m➜  Shareable Link:\x1b[0m \x1b[1m\x1b[36m\x1b[4m${tunnel.url}\x1b[0m\n`);
          } catch (e) {
            console.error('Tunnel error:', e);
          }
        });
      }
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tunnelPlugin()],
  server: {
    host: true,
    port: 3000,
    allowedHosts: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/scans': 'http://127.0.0.1:8000',
      '/assets': 'http://127.0.0.1:8000',
      '/cbom': 'http://127.0.0.1:8000',
      '/reports': 'http://127.0.0.1:8000',
      '/config': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
    },
  },
});
