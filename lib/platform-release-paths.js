'use strict';

/** Wasabi prefix for platform-wide SaaS release artifacts (shared bucket). */
const PLATFORM_RELEASES_ROOT = 'platform/releases';
const PLATFORM_RUNTIME_ROOT = 'platform/runtime';

function buildManifestKey() {
  return `${PLATFORM_RELEASES_ROOT}/manifest.json`;
}

function buildReleaseMetaKey(version) {
  return `${PLATFORM_RELEASES_ROOT}/${version}/release.json`;
}

function buildReleaseArtifactKey(version, name) {
  return `${PLATFORM_RELEASES_ROOT}/${version}/artifacts/${name}`;
}

function buildNonSaasRuntimeKey() {
  return `${PLATFORM_RUNTIME_ROOT}/non-saas-current.json`;
}

function buildSaasRuntimeKey() {
  return `${PLATFORM_RUNTIME_ROOT}/saas-deployed.json`;
}

module.exports = {
  PLATFORM_RELEASES_ROOT,
  PLATFORM_RUNTIME_ROOT,
  buildManifestKey,
  buildReleaseMetaKey,
  buildReleaseArtifactKey,
  buildNonSaasRuntimeKey,
  buildSaasRuntimeKey
};
