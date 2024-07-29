const webpackConfig = require('@nextcloud/webpack-vue-config')
const ESLintPlugin = require('eslint-webpack-plugin')
const StyleLintPlugin = require('stylelint-webpack-plugin')
const path = require('path')

webpackConfig.entry = {
	main: { import: path.join(__dirname, 'js', 'utils.js'), filename: 'utils.js' },
	utils: { import: path.join(__dirname, 'js', 'main.js'), filename: 'main.js' },
	autoSubmit: { import: path.join(__dirname, 'js', 'autoSubmit.js'), filename: 'autoSubmit.js' },
	eventListeners: { import: path.join(__dirname, 'js', 'eventListeners.js'), filename: 'eventListeners.js' },
	pollByReload: { import: path.join(__dirname, 'js', 'pollByReload.js'), filename: 'pollByReload.js' },
	pollInBrowser: { import: path.join(__dirname, 'js', 'pollInBrowser.js'), filename: 'pollInBrowser.js' },
	pollTransactionWorker: { import: path.join(__dirname, 'js', 'pollTransaction.worker.js'), filename: 'pollTransaction.worker.js' },
	webauthn: { import: path.join(__dirname, 'js', 'pi-webauthn.js'), filename: 'pi-webauthn.js' },
	settingsAdmin: { import: path.join(__dirname, 'js', 'settings-admin.js'), filename: 'settings-admin.js' },
}

webpackConfig.plugins.push(
	new ESLintPlugin({
		extensions: ['js', 'vue'],
		files: 'src',
	}),
)
webpackConfig.plugins.push(
	new StyleLintPlugin({
		files: 'src/**/*.{css,scss,vue}',
	}),
)

webpackConfig.module.rules.push({
	test: /\.svg$/i,
	type: 'asset/source',
})

module.exports = webpackConfig
