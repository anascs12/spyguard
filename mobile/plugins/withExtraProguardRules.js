const { withDangerousMod } = require("expo/config-plugins");
const fs = require("fs");
const path = require("path");

module.exports = function withExtraProguardRules(config) {
  return withDangerousMod(config, [
    "android",
    (config) => {
      const proguardPath = path.join(
        config.modRequest.platformProjectRoot,
        "app",
        "proguard-rules.pro"
      );
      const extra = [
        "",
        "# expo-av (R8 missing class warnings)",
        "-dontwarn expo.modules.core.interfaces.services.KeepAwakeManager",
        "-dontwarn expo.modules.kotlin.types.AnyTypeProvider",
        "-dontwarn expo.modules.kotlin.types.LazyKType",
        "",
      ].join("\n");

      const existing = fs.readFileSync(proguardPath, "utf8");
      if (!existing.includes("expo-av")) {
        fs.appendFileSync(proguardPath, extra);
      }
      return config;
    },
  ]);
};
