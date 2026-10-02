import {defineConfig} from 'vite';
import {svelte} from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
    plugins: [
        svelte({
            /* plugin options */
        })
    ],
    server: {
        port: 8094,
        open: true,
        proxy: {
            '/api': {
                target: 'http://localhost:8092',
                changeOrigin: false,
                secure: false
            }
        }
    },
});
