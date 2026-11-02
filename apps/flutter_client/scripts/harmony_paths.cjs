const fs = require('node:fs');
const path = require('node:path');

// Flutter-OH fixes its platform path at ohos/. The sources remain in harmony/.
// Keep this local alias available for both Studio and Flutter processes.
function ensureHarmonyAlias(appDir) {
  const source = path.join(appDir, 'harmony');
  const alias = path.join(appDir, 'ohos');
  if (!fs.existsSync(path.join(source, 'build-profile.json5'))) {
    throw new Error('Harmony platform project is missing.');
  }
  try {
    fs.symlinkSync('harmony', alias, 'dir');
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  if (!fs.lstatSync(alias).isSymbolicLink() ||
      path.resolve(appDir, fs.readlinkSync(alias)) !== source) {
    throw new Error('Refusing to replace an existing ohos path; expected a link to harmony.');
  }
}

module.exports = { ensureHarmonyAlias };
if (require.main === module) {
  ensureHarmonyAlias(path.resolve(__dirname, '..'));
}
