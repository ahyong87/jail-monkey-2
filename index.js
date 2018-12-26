const react = require('react')
const rn = require('react-native')
let JailMonkey = null

// Detect location of native modules to support RN < 0.28
if (react.NativeModules && react.NativeModules.JailMonkey) {
  JailMonkey = react.NativeModules.JailMonkey
} else {
  JailMonkey = rn.NativeModules.JailMonkey
}

export default {
  isNotOriginal: () => JailMonkey.isNotOriginal,
  canMockLocation: () => JailMonkey.canMockLocation,
  trustFall: () => JailMonkey.isNotOriginal !== 'This is safe to use!' || JailMonkey.canMockLocation,
  isOnExternalStorage: () => JailMonkey.isOnExternalStorage
}
