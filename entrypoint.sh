#!/bin/sh

# Fix permissions on mounted volumes to allow read/write for the nextjs user
chown -R nextjs:nodejs /app/uploads /app/modules /app/dev.db 2>/dev/null || true
chmod -R 777 /app/modules 2>/dev/null || true
chmod -R 777 /app/uploads 2>/dev/null || true
chmod 666 /app/dev.db 2>/dev/null || true

# Start the application
exec node server.js