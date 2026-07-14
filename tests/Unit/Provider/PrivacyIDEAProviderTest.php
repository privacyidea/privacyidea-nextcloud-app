<?php

/*
 * Copyright 2024 NetKnights GmbH
 *
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.
 */

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Tests\Unit\Provider;

use OCA\PrivacyIDEA\Provider\PrivacyIDEAFactory;
use OCA\PrivacyIDEA\Provider\PrivacyIDEAProvider;
use OCP\IAppConfig;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class PrivacyIDEAProviderTest extends TestCase
{
	/** @var array<string, mixed> */
	private array $sessionStore = [];

	/**
	 * Build a provider with a configurable app-config map. The session is
	 * backed by $this->sessionStore so we can assert what the provider wrote.
	 *
	 * @param array<string, string> $config
	 * @param callable|null $isInGroup fn(string $uid, string $group): bool
	 */
	private function makeProvider(array $config = [], ?callable $isInGroup = null, string $remoteAddr = '10.0.0.5'): PrivacyIDEAProvider
	{
		$appConfig = $this->createMock(IAppConfig::class);
		$appConfig->method('getValueString')->willReturnCallback(
			fn (string $app, string $key, string $default = '', bool $lazy = false): string => $config[$key] ?? $default
		);

		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn($remoteAddr);

		$groupManager = $this->createMock(IGroupManager::class);
		if ($isInGroup !== null) {
			$groupManager->method('isInGroup')->willReturnCallback($isInGroup);
		} else {
			$groupManager->method('isInGroup')->willReturn(false);
		}

		$trans = $this->createMock(IL10N::class);
		$trans->method('t')->willReturnArgument(0);

		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(fn (string $k) => $this->sessionStore[$k] ?? null);
		$session->method('set')->willReturnCallback(function (string $k, $v): void {
			$this->sessionStore[$k] = $v;
		});

		$factory = $this->createMock(PrivacyIDEAFactory::class);

		return new PrivacyIDEAProvider(
			$appConfig,
			$this->createMock(LoggerInterface::class),
			$request,
			$groupManager,
			$trans,
			$session,
			$factory
		);
	}

	private function user(string $uid = 'alice'): IUser
	{
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		return $user;
	}

	// ---- getHeadersToForward: regression test for the array_push bug ----

	public function testHeadersToForwardBuildsFlatHeaderStrings(): void
	{
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';
		$_SERVER['HTTP_X_CUSTOM'] = 'value2';
		try {
			$provider = $this->makeProvider();
			$method = new \ReflectionMethod($provider, 'getHeadersToForward');
			$method->setAccessible(true);

			/** @var array $result */
			$result = $method->invoke($provider, 'HTTP_X_FORWARDED_FOR, HTTP_X_CUSTOM');

			// The old code assigned array_push()'s int return -> broke on the
			// 2nd header and produced malformed entries. Assert flat strings.
			self::assertSame(
				['HTTP_X_FORWARDED_FOR: 203.0.113.9', 'HTTP_X_CUSTOM: value2'],
				$result
			);
		} finally {
			unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_CUSTOM']);
		}
	}

	public function testHeadersToForwardSkipsMissingHeaders(): void
	{
		unset($_SERVER['HTTP_NOT_PRESENT']);
		$provider = $this->makeProvider();
		$method = new \ReflectionMethod($provider, 'getHeadersToForward');
		$method->setAccessible(true);

		self::assertSame([], $method->invoke($provider, 'HTTP_NOT_PRESENT'));
	}

	// ---- processPIResponse: regression test for the null-deref fix ----

	public function testProcessNullResponseDoesNotThrowAndSetsErrorMessage(): void
	{
		$this->sessionStore = [];
		$provider = $this->makeProvider();
		$method = new \ReflectionMethod($provider, 'processPIResponse');
		$method->setAccessible(true);

		$method->invoke($provider, null); // must not raise a TypeError

		self::assertArrayHasKey('piErrorMessage', $this->sessionStore);
		self::assertNotEmpty($this->sessionStore['piErrorMessage']);
	}

	// ---- isTwoFactorAuthEnabledForUser ----

	public function testDisabledWhenPiNotActivated(): void
	{
		$provider = $this->makeProvider(['piActivatePI' => '0']);
		self::assertFalse($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testEnabledWhenActiveAndNoGroupRestrictions(): void
	{
		$provider = $this->makeProvider(['piActivatePI' => '1']);
		self::assertTrue($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testExcludedGroupMemberIsNotRequiredToUseMfa(): void
	{
		$provider = $this->makeProvider(
			[
				'piActivatePI' => '1',
				'piInExGroupsField' => 'admins',
				'piInOrExSelected' => 'exclude',
			],
			fn (string $uid, string $group): bool => $group === 'admins'
		);
		self::assertFalse($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testIncludedGroupMemberIsRequiredToUseMfa(): void
	{
		$provider = $this->makeProvider(
			[
				'piActivatePI' => '1',
				'piInExGroupsField' => 'vip',
				'piInOrExSelected' => 'include',
			],
			fn (string $uid, string $group): bool => $group === 'vip'
		);
		self::assertTrue($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testExcludedIpAddressDisablesMfa(): void
	{
		$provider = $this->makeProvider(
			['piActivatePI' => '1', 'piExcludeIPs' => '10.0.0.5'],
			null,
			'10.0.0.5'
		);
		self::assertFalse($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testExcludedIpRangeDisablesMfa(): void
	{
		$provider = $this->makeProvider(
			['piActivatePI' => '1', 'piExcludeIPs' => '10.0.0.1-10.0.0.100'],
			null,
			'10.0.0.5'
		);
		self::assertFalse($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testStaticMetadataAccessors(): void
	{
		$provider = $this->makeProvider();
		self::assertSame('privacyidea', $provider->getId());
		self::assertNotEmpty($provider->getDisplayName());
		self::assertNotEmpty($provider->getDescription());
	}
}
