// Sign release builds with the key named in ~/.gradle/gradle.properties:
//   PRIVACY_SCANNER_STORE_FILE, PRIVACY_SCANNER_KEY_ALIAS,
//   PRIVACY_SCANNER_STORE_PASSWORD, PRIVACY_SCANNER_KEY_PASSWORD
// Without those properties, release builds keep Expo's default (debug key).
const { withAppBuildGradle } = require('expo/config-plugins');

const MARKER = '// privacy-scanner release signing';

module.exports = function withReleaseSigning(config) {
  return withAppBuildGradle(config, (cfg) => {
    let gradle = cfg.modResults.contents;
    if (gradle.includes(MARKER)) return cfg;

    gradle = gradle.replace(
      /signingConfigs\s*\{/,
      `signingConfigs {
        ${MARKER}
        if (project.hasProperty('PRIVACY_SCANNER_STORE_FILE')) {
            release {
                storeFile file(PRIVACY_SCANNER_STORE_FILE)
                storePassword PRIVACY_SCANNER_STORE_PASSWORD
                keyAlias PRIVACY_SCANNER_KEY_ALIAS
                keyPassword PRIVACY_SCANNER_KEY_PASSWORD
            }
        }`,
    );
    // In the release buildType, prefer the release key when it's configured
    gradle = gradle.replace(
      /(release\s*\{[^}]*?)signingConfig\s+signingConfigs\.debug/,
      "$1signingConfig project.hasProperty('PRIVACY_SCANNER_STORE_FILE') ? signingConfigs.release : signingConfigs.debug",
    );
    cfg.modResults.contents = gradle;
    return cfg;
  });
};
