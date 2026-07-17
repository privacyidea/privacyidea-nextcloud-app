<?php

/*
 * Copyright 2024 NetKnights GmbH
 *
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.
 */

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Tests\Unit\Provider;

use OCA\PrivacyIDEA\PIClient\PrivacyIDEA;
use OCA\PrivacyIDEA\Provider\PrivacyIDEAFactory;
use OCP\App\IAppManager;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IRequest;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class PrivacyIDEAFactoryTest extends TestCase
{
	/**
	 * @param array<string, string> $config
	 */
	private function factory(array $config, string $appVersion = '9.9.9'): PrivacyIDEAFactory
	{
		$appConfig = $this->createMock(IAppConfig::class);
		$appConfig->method('getValueString')->willReturnCallback(
			fn (string $app, string $key, string $default = '', bool $lazy = false): string => $config[$key] ?? $default
		);

		$appManager = $this->createMock(IAppManager::class);
		$appManager->method('getAppVersion')->willReturn($appVersion);

		return new PrivacyIDEAFactory(
			$appConfig,
			$this->createMock(IRequest::class),
			$this->createMock(LoggerInterface::class),
			$appManager,
			$this->createMock(IConfig::class)
		);
	}

	public function testUserAgentIsDerivedFromAppVersion(): void
	{
		$pi = $this->factory(['piURL' => 'https://pi.example.com'], '2.5.0')->create();

		self::assertInstanceOf(PrivacyIDEA::class, $pi);

		// The user agent is private and has no getter; read it reflectively to
		// prove it is built from the manifest version (single source of truth).
		$prop = new \ReflectionProperty(PrivacyIDEA::class, 'userAgent');
		$prop->setAccessible(true);
		self::assertSame('privacyidea-nextcloud/2.5.0', $prop->getValue($pi));
	}

	public function testReturnsNullWhenServerUrlMissing(): void
	{
		self::assertNull($this->factory([])->create());
	}
}
