import path from 'path'
import { injectNativeModules } from 'flutter-hvigor-plugin';

const { ensureHarmonyAlias } = require('../scripts/harmony_paths.cjs');

ensureHarmonyAlias(path.dirname(__dirname));
injectNativeModules(__dirname, path.dirname(__dirname));
