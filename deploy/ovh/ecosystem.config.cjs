/** PM2 — run from /opt/horizon/horizon-backend: pm2 start deploy/ovh/ecosystem.config.cjs */
module.exports = {
  apps: [
    {
      name: 'horizon-backend',
      cwd: '/opt/horizon/horizon-backend',
      script: 'server.js',
      instances: 4,
      exec_mode: 'cluster',
      max_memory_restart: '1500M',
      env: {
        NODE_ENV: 'production'
      },
      error_file: '/var/log/horizon/pm2-error.log',
      out_file: '/var/log/horizon/pm2-out.log',
      merge_logs: true,
      time: true
    }
  ]
};
