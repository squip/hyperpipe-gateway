import { config as loadEnv } from 'dotenv';

import { loadConfig, loadTlsOptions } from './config.mjs';
import { createLogger } from './logger.mjs';
import PublicGatewayService from './PublicGatewayService.mjs';
import { createRegistrationStore } from './stores/index.mjs';
import { installStdoutLogRotation } from './utils/stdout-log-rotator.mjs';

async function main() {
  loadEnv();

  installStdoutLogRotation({
    logDir: process.env.GATEWAY_LOG_DIR || null,
    rotateMs: process.env.GATEWAY_LOG_ROTATE_MS || null,
    retentionMs: process.env.GATEWAY_LOG_RETENTION_MS || null,
    prefix: process.env.GATEWAY_LOG_PREFIX || null
  });

  const logger = createLogger();

  try {
    const config = loadConfig();
    const tlsOptions = await loadTlsOptions(config.tls);
    const registrationStore = await createRegistrationStore(config.registration, logger);

    const service = new PublicGatewayService({
      config,
      logger,
      tlsOptions,
      registrationStore
    });

    await service.init();
    await service.start();

    process.on('SIGINT', async () => {
      logger.info('Received SIGINT, shutting down');
      await service.stop();
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      logger.info('Received SIGTERM, shutting down');
      await service.stop();
      process.exit(0);
    });
  } catch (error) {
    logger.error({ err: error }, 'Gateway failed to start');
    process.exitCode = 1;
  }
}

main();
