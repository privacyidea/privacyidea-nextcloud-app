<?php

/*
 * PHPUnit bootstrap for the privacyIDEA Nextcloud app.
 *
 * Loads the root Composer autoloader, which provides:
 *   - the app's own classes (OCA\PrivacyIDEA\*, PSR-4 -> lib/)
 *   - the test classes (OCA\PrivacyIDEA\Tests\*, PSR-4 -> tests/)
 *   - the Nextcloud OCP interface stubs (nextcloud/ocp, dev dependency)
 *
 * PHPUnit itself is autoloaded by its own runtime (installed as a
 * composer-bin package under vendor-bin/phpunit).
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

// nextcloud/ocp declares an empty autoload block on purpose: a real
// Nextcloud server provides the OCP\* interfaces at runtime, so the package
// exists only as stubs for static analysis. Register them here so mocks of
// OCP interfaces resolve under PHPUnit.
spl_autoload_register(static function (string $class): void {
	if (!str_starts_with($class, 'OCP\\')) {
		return;
	}
	$path = __DIR__ . '/../vendor/nextcloud/ocp/' . str_replace('\\', '/', $class) . '.php';
	if (is_file($path)) {
		require_once $path;
	}
});
