<?php

/*
 * Copyright 2024 NetKnights GmbH
 *
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.
 */

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Tests\Unit\Provider;

use OCA\PrivacyIDEA\PIClient\PIResponse;
use OCA\PrivacyIDEA\PIClient\PrivacyIDEA;
use OCA\PrivacyIDEA\Provider\PrivacyIDEAFactory;
use OCA\PrivacyIDEA\Provider\PrivacyIDEAProvider;
use OCP\Authentication\LoginCredentials\ICredentials;
use OCP\Authentication\LoginCredentials\IStore;
use OCP\Authentication\TwoFactorAuth\TwoFactorException;
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
	 * @param array<string, string> $requestParams values returned by IRequest::getParam
	 * @param PrivacyIDEA|null $pi client returned by the factory when piAllowCreatingPIInstance is set
	 * @param string|null $loginPassword first-factor password the store returns; null makes it throw (unavailable, as for SSO/passkey logins)
	 */
	private function makeProvider(array $config = [], ?callable $isInGroup = null, string $remoteAddr = '10.0.0.5', array $requestParams = [], ?PrivacyIDEA $pi = null, ?string $loginPassword = null): PrivacyIDEAProvider
	{
		$appConfig = $this->createMock(IAppConfig::class);
		$appConfig->method('getValueString')->willReturnCallback(
			fn (string $app, string $key, string $default = '', bool $lazy = false): string => $config[$key] ?? $default
		);

		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn($remoteAddr);
		$request->method('getParam')->willReturnCallback(
			fn (string $key, $default = null) => $requestParams[$key] ?? $default
		);

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
		$factory->method('create')->willReturn($pi);

		$credentialStore = $this->createMock(IStore::class);
		if ($loginPassword === null) {
			$credentialStore->method('getLoginCredentials')->willThrowException(new \RuntimeException('unavailable'));
		} else {
			$creds = $this->createMock(ICredentials::class);
			$creds->method('getPassword')->willReturn($loginPassword);
			$credentialStore->method('getLoginCredentials')->willReturn($creds);
		}

		return new PrivacyIDEAProvider(
			$appConfig,
			$this->createMock(LoggerInterface::class),
			$request,
			$groupManager,
			$trans,
			$session,
			$factory,
			$credentialStore
		);
	}

	private function user(string $uid = 'alice'): IUser
	{
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($uid);
		return $user;
	}

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

			// Flat strings (the old code broke on the 2nd header), forwarded
			// under the real HTTP header name rather than the $_SERVER key.
			self::assertSame(
				['X-Forwarded-For: 203.0.113.9', 'X-Custom: value2'],
				$result
			);
		} finally {
			unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_CUSTOM']);
		}
	}

	public function testHeadersToForwardAcceptsNaturalHeaderNames(): void
	{
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';
		$_SERVER['REMOTE_ADDR'] = '198.51.100.4';
		try {
			$provider = $this->makeProvider();
			$method = new \ReflectionMethod($provider, 'getHeadersToForward');
			$method->setAccessible(true);

			// The natural header name resolves to its HTTP_ server variable, and
			// a raw non-HTTP server variable is accepted as-is; both are
			// forwarded under a real HTTP header name.
			$result = $method->invoke($provider, 'X-Forwarded-For, REMOTE_ADDR');

			self::assertSame(
				['X-Forwarded-For: 203.0.113.9', 'Remote-Addr: 198.51.100.4'],
				$result
			);
		} finally {
			unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['REMOTE_ADDR']);
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

	public function testWebauthnImageIsStoredUnderTheKeyTheTemplateReads(): void
	{
		// processPIResponse stored the image under 'piImgWebAuthn' while
		// getTemplate reads 'piImgWebauthn'; the two must use the same key or
		// the WebAuthn image never reaches the template.
		$response = PIResponse::fromJSON(
			'{"detail":{"multi_challenge":[{"type":"webauthn","serial":"WAN1","transaction_id":"tx","message":"m","client_mode":"webauthn","image":"data:image/png;base64,ZZ","attributes":{"webAuthnSignRequest":{"allowCredentials":[{"id":"c","type":"public-key"}],"challenge":"ch","rpId":"rp"}}}],"transaction_id":"tx","type":"webauthn"},"result":{"authentication":"CHALLENGE","status":true,"value":false}}',
			$this->createMock(PrivacyIDEA::class)
		);

		$this->sessionStore = [];
		$provider = $this->makeProvider();
		$method = new \ReflectionMethod($provider, 'processPIResponse');
		$method->setAccessible(true);
		$method->invoke($provider, $response);

		self::assertSame('data:image/png;base64,ZZ', $this->sessionStore['piImgWebauthn'] ?? null);
	}

	public function testPreferredClientModeWinsOverACoexistingPasskeyChallenge(): void
	{
		// A push+passkey challenge whose preferred_client_mode is "interactive"
		// must start on the OTP field, not force the page into passkey mode. The
		// passkey challenge is still stored so the passkey login option works.
		$response = PIResponse::fromJSON(
			'{"detail":{"client_mode":"interactive","multi_challenge":['
			. '{"client_mode":"webauthn","serial":"PIPK0004","transaction_id":"tx","type":"passkey","message":"Touch your authenticator!"},'
			. '{"client_mode":"interactive","serial":"PIPU0003","transaction_id":"tx","type":"push","message":"Please enter the code displayed on your smartphone."}'
			. '],"preferred_client_mode":"interactive","transaction_id":"tx","type":"push"},'
			. '"result":{"authentication":"CHALLENGE","status":true,"value":false}}',
			$this->createMock(PrivacyIDEA::class)
		);

		$this->sessionStore = [];
		$provider = $this->makeProvider();
		$method = new \ReflectionMethod($provider, 'processPIResponse');
		$method->setAccessible(true);
		$method->invoke($provider, $response);

		self::assertSame('otp', $this->sessionStore['piMode'] ?? null);
		self::assertNotEmpty($this->sessionStore['piPasskeyChallenge'] ?? null);
	}

	public function testPasskeyOnlyChallengeUsesPasskeyMode(): void
	{
		// A passkey challenge reports client_mode "webauthn"; with no competing
		// token the page must run the dedicated passkey flow, not WebAuthn.
		$response = PIResponse::fromJSON(
			'{"detail":{"client_mode":"webauthn","multi_challenge":['
			. '{"client_mode":"webauthn","serial":"PIPK0004","transaction_id":"tx","type":"passkey","message":"Touch your authenticator!"}'
			. '],"preferred_client_mode":"webauthn","transaction_id":"tx","type":"passkey"},'
			. '"result":{"authentication":"CHALLENGE","status":true,"value":false}}',
			$this->createMock(PrivacyIDEA::class)
		);

		$this->sessionStore = [];
		$provider = $this->makeProvider();
		$method = new \ReflectionMethod($provider, 'processPIResponse');
		$method->setAccessible(true);
		$method->invoke($provider, $response);

		self::assertSame('passkey', $this->sessionStore['piMode'] ?? null);
	}

	public function testPreferredPollModeMapsToPush(): void
	{
		// preferred_client_mode "poll" (push + HOTP) starts the page in push mode.
		$response = PIResponse::fromJSON(
			'{"detail":{"client_mode":"poll","multi_challenge":['
			. '{"client_mode":"poll","serial":"PIPU0003","transaction_id":"tx","type":"push","message":"Please confirm on your phone."},'
			. '{"client_mode":"interactive","serial":"HOTP1","transaction_id":"tx","type":"hotp","message":"Enter OTP."}'
			. '],"preferred_client_mode":"poll","transaction_id":"tx","type":"push"},'
			. '"result":{"authentication":"CHALLENGE","status":true,"value":false}}',
			$this->createMock(PrivacyIDEA::class)
		);

		$this->sessionStore = [];
		$provider = $this->makeProvider();
		$method = new \ReflectionMethod($provider, 'processPIResponse');
		$method->setAccessible(true);
		$method->invoke($provider, $response);

		self::assertSame('push', $this->sessionStore['piMode'] ?? null);
	}

	public function testWebauthnVerifyForwardsRawSignResponse(): void
	{
		// The sign response must be forwarded to the client verbatim, without a
		// decode/re-encode round-trip that could alter the payload.
		$signResponse = '{"credentialid":"c","clientdata":"cd","signaturedata":"s","authenticatordata":"a"}';
		$pi = $this->createMock(PrivacyIDEA::class);
		$accept = PIResponse::fromJSON(
			'{"result":{"authentication":"ACCEPT","status":true,"value":true}}',
			$pi
		);
		$pi->expects(self::once())
			->method('validateCheckWebAuthn')
			->with('alice', 'tx-w', $signResponse, 'https://x', self::anything())
			->willReturn($accept);

		$this->sessionStore = [
			'piAllowCreatingPIInstance' => true,
			'piTransactionID' => 'tx-w',
		];
		$provider = $this->makeProvider([], null, '10.0.0.5', [
			'mode' => 'webauthn',
			'webAuthnSignResponse' => $signResponse,
			'origin' => 'https://x',
		], $pi);

		self::assertTrue($provider->verifyChallenge($this->user(), ''));
	}

	public function testCancelOptionalEnrollmentCompletesAuthentication(): void
	{
		// Cancelling an optional enroll_via_multichallenge returns ACCEPT, which
		// must complete the 2FA step.
		$pi = $this->createMock(PrivacyIDEA::class);
		$cancelResponse = PIResponse::fromJSON(
			'{"detail": {"message": "Cancelled enrollment via multichallenge"}, "result": {"authentication": "ACCEPT", "status": true, "value": true}}',
			$pi
		);
		$pi->expects(self::once())
			->method('validateCheckCancelEnrollment')
			->with('08062584491116057815', self::anything())
			->willReturn($cancelResponse);

		// Constructor only builds the client when this flag is set.
		$this->sessionStore = [
			'piAllowCreatingPIInstance' => true,
			'piTransactionID' => '08062584491116057815',
		];
		$provider = $this->makeProvider([], null, '10.0.0.5', ['enrollmentCancelled' => '1'], $pi);

		self::assertTrue($provider->verifyChallenge($this->user(), ''));
	}

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

	public function testIpv6ClientIsNotBypassedByExcludeRule(): void
	{
		// ip2long() returns false for an IPv6 client address; that false must not
		// compare equal to the false of an unparseable exclude entry and skip
		// MFA, so an IPv6 client still gets two-factor authentication.
		$provider = $this->makeProvider(
			['piActivatePI' => '1', 'piExcludeIPs' => '10.0.0.5,2001:db8::1'],
			null,
			'2001:db8::99'
		);
		self::assertTrue($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testMalformedExcludeEntryDoesNotBypassMfa(): void
	{
		// A non-parseable exclude entry (hostname / trailing comma) must be
		// skipped, not treated as a match for an IPv4 client.
		$provider = $this->makeProvider(
			['piActivatePI' => '1', 'piExcludeIPs' => 'not-an-ip,'],
			null,
			'10.0.0.5'
		);
		self::assertTrue($provider->isTwoFactorAuthEnabledForUser($this->user()));
	}

	public function testVerifyChallengeWithoutClientThrowsCleanly(): void
	{
		// When the client was never created (server URL missing or the session
		// flag lost) verifyChallenge must raise a handled TwoFactorException,
		// not a fatal "typed property not initialized" Error.
		$provider = $this->makeProvider(); // no piAllowCreatingPIInstance -> $pi is null
		$this->expectException(TwoFactorException::class);
		$provider->verifyChallenge($this->user(), '123456');
	}

	public function testPushLoadCounterIsCastAndDoesNotTypeError(): void
	{
		// A tampered non-numeric loadCounter must not raise a TypeError on
		// `$counter + 1`; the push flow ends in a benign TwoFactorException.
		$pi = $this->createMock(PrivacyIDEA::class);
		$pi->method('pollTransaction')->willReturn(false);

		$this->sessionStore = [
			'piAllowCreatingPIInstance' => true,
			'piTransactionID' => 'tx-push',
		];
		$provider = $this->makeProvider(
			[],
			null,
			'10.0.0.5',
			['mode' => 'push', 'loadCounter' => 'abc'],
			$pi
		);

		$this->expectException(TwoFactorException::class);
		$provider->verifyChallenge($this->user(), '');
	}

	public function testGetLoginPasswordReturnsTheStoredPassword(): void
	{
		$provider = $this->makeProvider([], null, '10.0.0.5', [], null, 's3cret');
		$method = new \ReflectionMethod($provider, 'getLoginPassword');
		$method->setAccessible(true);
		self::assertSame('s3cret', $method->invoke($provider));
	}

	public function testGetLoginPasswordIsEmptyWhenUnavailable(): void
	{
		// SSO / passkey / token logins: the credential store throws -> empty string.
		$provider = $this->makeProvider([], null, '10.0.0.5', [], null, null);
		$method = new \ReflectionMethod($provider, 'getLoginPassword');
		$method->setAccessible(true);
		self::assertSame('', $method->invoke($provider));
	}

	public function testStaticMetadataAccessors(): void
	{
		$provider = $this->makeProvider();
		self::assertSame('privacyidea', $provider->getId());
		self::assertNotEmpty($provider->getDisplayName());
		self::assertNotEmpty($provider->getDescription());
	}
}
