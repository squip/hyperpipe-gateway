import MemoryRegistrationStore from './MemoryRegistrationStore.mjs';
import RedisRegistrationStore from './RedisRegistrationStore.mjs';

async function createRegistrationStore(config = {}, logger) {
  if (config?.redisUrl) {
    try {
      const store = new RedisRegistrationStore({
        url: config.redisUrl,
        ttlSeconds: config.cacheTtlSeconds,
        relayTtlSeconds: config.relayTtlSeconds,
        aliasTtlSeconds: config.aliasTtlSeconds,
        tokenTtlSeconds: config.tokenTtlSeconds,
        mirrorTtlSeconds: config.mirrorTtlSeconds,
        openJoinPoolTtlSeconds: config.openJoinPoolTtlSeconds,
        prefix: config.redisPrefix,
        logger
      });
      await store.connect();
      logger?.info?.('Using Redis registration store');
      return store;
    } catch (error) {
      logger?.error?.('Failed to initialize Redis registration store, falling back to memory cache', { error: error.message });
    }
  }

  return new MemoryRegistrationStore({
    ttlSeconds: config?.cacheTtlSeconds,
    relayTtlSeconds: config?.relayTtlSeconds,
    aliasTtlSeconds: config?.aliasTtlSeconds,
    tokenTtlSeconds: config?.tokenTtlSeconds,
    mirrorTtlSeconds: config?.mirrorTtlSeconds,
    openJoinPoolTtlSeconds: config?.openJoinPoolTtlSeconds
  });
}

export {
  createRegistrationStore
};
