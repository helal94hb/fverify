/**
 * Entry point. Standalone app — registers its own root component and shares
 * NOTHING with the digital-banking mobile app (owner ruling 2026-08-29).
 */

import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
