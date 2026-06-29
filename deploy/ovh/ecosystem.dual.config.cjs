/**
 * Dual PipeShare backends on one OVH box — Base (private) + SaaS (subscription).
 *
 *   pm2 start deploy/ovh/ecosystem.dual.config.cjs
 *   pm2 save
 *
 * Env files (create from templates, chmod 600):
 *   /opt/horizon/horizon-backend/.env.base   — HP_DEPLOYMENT_MODE=non-saas, PORT=3000
 *   /opt/horizon/horizon-backend/.env.saas   — HP_DEPLOYMENT_MODE=saas, PORT=3001
 */
module.exports = {
  apps: [
    {
      name: 'horizon-backend-base',
      cwd: '/opt/horizon/horizon-backend',
      script: 'server.js',
      instances: 2,
      exec_mode: 'cluster',
      env_file: '/opt/horizon/horizon-backend/.env.base',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        HP_DEPLOYMENT_MODE: 'non-saas',
        HP_PM2_APP_NAME: 'horizon-backend-base'
      },
      max_memory_restart: '750M',
      merge_logs: true,
      time: true
    },
    {
      name: 'horizon-backend-saas',
      cwd: '/opt/horizon/horizon-backend',
      script: 'server.js',
      instances: 2,
      exec_mode: 'cluster',
      env_file: '/opt/horizon/horizon-backend/.env.saas',
      env: {
        NODE_ENV: 'production',
        PORT: 3001,
        HP_DEPLOYMENT_MODE: 'saas',
        HP_PM2_APP_NAME: 'horizon-backend-saas',
        HP_PLATFORM_APPLY_SCRIPT: '/opt/horizon/horizon-backend/deploy/saas/apply-platform-release.sh'
      },
      max_memory_restart: '750M',
      merge_logs: true,
      time: true
    }
  ]
};
