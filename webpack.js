const webpackConfig = require('@nextcloud/webpack-vue-config')
const path = require('path')

webpackConfig.entry = {
	webauthn: { import: path.join(__dirname, 'js', 'piWebAuthn.js'), filename: 'piWebAuthn.js' },
	main: { import: path.join(__dirname, 'js', 'utils.js'), filename: 'utils.js' },
	utils: { import: path.join(__dirname, 'js', 'main.js'), filename: 'main.js' },
	eventListeners: { import: path.join(__dirname, 'js', 'eventListeners.js'), filename: 'eventListeners.js' },
	pollTransactionWorker: { import: path.join(__dirname, 'js', 'pollTransaction.worker.js'), filename: 'pollTransaction.worker.js' },
	settingsAdmin: { import: path.join(__dirname, 'js', 'settings-admin.js'), filename: 'settings-admin.js' },
}

module.exports = webpackConfig