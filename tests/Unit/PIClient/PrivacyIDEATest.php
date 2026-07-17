<?php

/*
 * Copyright 2024 NetKnights GmbH
 *
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.
 */

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Tests\Unit\PIClient;

use OCA\PrivacyIDEA\PIClient\PrivacyIDEA;
use PHPUnit\Framework\TestCase;

/**
 * PrivacyIDEA subclass that replaces the cURL transport seam with an
 * in-memory recorder, so client methods can be tested without a network.
 */
class TestablePrivacyIDEA extends PrivacyIDEA
{
	/** @var array<int, array{url: string, params: array, headers: array, method: string}> */
	public array $captured = [];

	/** @var array<string, string> endpoint-substring => canned response body */
	public array $responses = [];

	protected function curlRequest(string $completeUrl, array $params, array $headers, string $httpMethod): string
	{
		$this->captured[] = ['url' => $completeUrl, 'params' => $params, 'headers' => $headers, 'method' => $httpMethod];
		foreach ($this->responses as $needle => $body) {
			if (str_contains($completeUrl, $needle)) {
				return $body;
			}
		}
		return '{"result": {"status": true, "value": true, "authentication": "ACCEPT"}}';
	}

	// Silence logging (the real log() calls the OCP\Log\logger() helper).
	public function log($level, $message): void
	{
	}

	/** @return array{url: string, params: array, headers: array, method: string} */
	public function lastRequest(): array
	{
		return $this->captured[count($this->captured) - 1];
	}
}

class PrivacyIDEATest extends TestCase
{
	private function client(): TestablePrivacyIDEA
	{
		return new TestablePrivacyIDEA('test-ua/1.0', 'https://pi.example.com');
	}

	public function testValidateCheckSendsUserAndPass(): void
	{
		$pi = $this->client();
		$pi->validateCheck('alice', 'secret123');

		$req = $pi->lastRequest();
		self::assertSame('POST', $req['method']);
		self::assertStringEndsWith('/validate/check', $req['url']);
		self::assertSame('alice', $req['params']['user']);
		self::assertSame('secret123', $req['params']['pass']);
		self::assertArrayNotHasKey('transaction_id', $req['params']);
	}

	public function testValidateCheckIncludesRealmAndTransactionId(): void
	{
		$pi = $this->client();
		$pi->setRealm('myrealm');
		$pi->validateCheck('alice', '', 'tx-42');

		$req = $pi->lastRequest();
		self::assertSame('myrealm', $req['params']['realm']);
		self::assertSame('tx-42', $req['params']['transaction_id']);
	}

	public function testValidateCheckReturnsNullOnEmptyUsernameWithoutRequest(): void
	{
		$pi = $this->client();
		$result = $pi->validateCheck('', 'secret');

		self::assertNull($result);
		self::assertCount(0, $pi->captured, 'No HTTP request must be made for an empty username');
	}

	public function testValidateCheckParsesAcceptResponse(): void
	{
		$pi = $this->client();
		$pi->responses['/validate/check'] =
			'{"detail": {"serial": "TOTP1"}, "result": {"status": true, "value": true, "authentication": "ACCEPT"}}';

		$response = $pi->validateCheck('alice', 'pin123456');

		self::assertNotNull($response);
		self::assertTrue($response->isAuthenticationSuccessful());
		self::assertSame('TOTP1', $response->getSerial());
	}

	public function testPollTransactionReturnsValueBoolean(): void
	{
		$pi = $this->client();

		$pi->responses['/validate/polltransaction'] = '{"result": {"status": true, "value": true}}';
		self::assertTrue($pi->pollTransaction('tx-1'));

		$pi->responses['/validate/polltransaction'] = '{"result": {"status": true, "value": false}}';
		self::assertFalse($pi->pollTransaction('tx-1'));

		$last = $pi->lastRequest();
		self::assertSame('GET', $last['method']);
		self::assertSame('tx-1', $last['params']['transaction_id']);
	}

	public function testPollTransactionReturnsFalseOnEmptyId(): void
	{
		$pi = $this->client();
		self::assertFalse($pi->pollTransaction(''));
		self::assertCount(0, $pi->captured);
	}

	public function testValidateCheckPasskeyBuildsParamsAndOriginHeader(): void
	{
		$pi = $this->client();
		$passkeyResponse = json_encode([
			'credential_id' => 'cred-abc',
			'clientDataJSON' => 'Y2xpZW50',
			'signature' => 'c2ln',
			'authenticatorData' => 'YXV0aA==',
			'userHandle' => 'dXNlcg==',
		]);

		$pi->validateCheckPasskey('tx-pk', $passkeyResponse, 'https://cloud.example.com:8443');

		$req = $pi->lastRequest();
		self::assertSame('tx-pk', $req['params']['transaction_id']);
		self::assertSame('cred-abc', $req['params']['credential_id']);
		self::assertSame('Y2xpZW50', $req['params']['clientDataJSON']);
		self::assertSame('c2ln', $req['params']['signature']);
		self::assertSame('YXV0aA==', $req['params']['authenticatorData']);
		self::assertSame('dXNlcg==', $req['params']['userHandle']);
		self::assertContains('Origin:https://cloud.example.com:8443', $req['headers']);
	}

	public function testValidateCheckPasskeyReturnsNullOnInvalidJson(): void
	{
		$pi = $this->client();
		$result = $pi->validateCheckPasskey('tx', 'not-json', 'https://x');

		self::assertNull($result);
		self::assertCount(0, $pi->captured);
	}

	public function testGetAuthTokenReturnsTokenForAdmin(): void
	{
		$pi = $this->client();
		$pi->setServiceAccountName('svc');
		$pi->setServiceAccountPass('pw');
		$pi->responses['/auth'] =
			'{"result": {"status": true, "value": {"token": "JWT-TOKEN", "role": "admin"}}}';

		self::assertSame('JWT-TOKEN', $pi->getAuthToken());
	}

	public function testGetAuthTokenRejectsNonAdminRole(): void
	{
		$pi = $this->client();
		$pi->setServiceAccountName('svc');
		$pi->setServiceAccountPass('pw');
		$pi->responses['/auth'] =
			'{"result": {"status": true, "value": {"token": "JWT-TOKEN", "role": "user"}}}';

		self::assertSame('', $pi->getAuthToken());
	}

	public function testGetAuthTokenWithoutServiceAccountReturnsEmpty(): void
	{
		$pi = $this->client();
		self::assertFalse($pi->serviceAccountAvailable());
		self::assertSame('', $pi->getAuthToken());
		self::assertCount(0, $pi->captured);
	}

	public function testValidateCheckCancelEnrollmentSendsCancelParam(): void
	{
		$pi = $this->client();
		$pi->responses['/validate/check'] =
			'{"detail": {"message": "Cancelled enrollment via multichallenge"}, "result": {"authentication": "ACCEPT", "status": true, "value": true}}';

		$response = $pi->validateCheckCancelEnrollment('08062584491116057815');

		$req = $pi->lastRequest();
		self::assertSame('POST', $req['method']);
		self::assertStringEndsWith('/validate/check', $req['url']);
		self::assertSame('08062584491116057815', $req['params']['transaction_id']);
		self::assertSame('true', $req['params']['cancel_enrollment']);
		self::assertArrayNotHasKey('user', $req['params']);

		self::assertNotNull($response);
		self::assertTrue($response->isAuthenticationSuccessful());
		self::assertSame('Cancelled enrollment via multichallenge', $response->getMessage());
	}

	public function testValidateCheckCancelEnrollmentRefusedIsNotSuccessful(): void
	{
		$pi = $this->client();
		$pi->responses['/validate/check'] =
			'{"detail": {"message": "Failed to cancel enrollment via multichallenge"}, "result": {"authentication": "REJECT", "status": true, "value": false}}';

		$response = $pi->validateCheckCancelEnrollment('13880467565432322008');

		self::assertNotNull($response);
		self::assertFalse($response->isAuthenticationSuccessful());
		self::assertSame('', $response->getErrorMessage());
		self::assertSame('Failed to cancel enrollment via multichallenge', $response->getMessage());
	}

	public function testValidateCheckCancelEnrollmentReturnsNullOnEmptyTransactionId(): void
	{
		$pi = $this->client();
		self::assertNull($pi->validateCheckCancelEnrollment(''));
		self::assertCount(0, $pi->captured);
	}

	public function testValidateCheckWebAuthnForwardsLowercaseUserHandle(): void
	{
		// The pi-webauthn JS library emits the field as "userhandle"; the client
		// must still forward it (previously it read only "userHandle" and dropped it).
		$pi = $this->client();
		$signResponse = json_encode([
			'credentialid' => 'cred-1',
			'clientdata' => 'Y2xpZW50',
			'signaturedata' => 'c2ln',
			'authenticatordata' => 'YXV0aA',
			'userhandle' => 'dXNlcg',
		]);

		$pi->validateCheckWebAuthn('alice', 'tx-w', $signResponse, 'https://x');

		$req = $pi->lastRequest();
		self::assertSame('cred-1', $req['params']['credentialid']);
		self::assertSame('dXNlcg', $req['params']['userHandle']);
	}

	public function testValidateCheckWebAuthnAcceptsCamelCaseUserHandle(): void
	{
		$pi = $this->client();
		$signResponse = json_encode([
			'credentialid' => 'cred-1',
			'clientdata' => 'Y2xpZW50',
			'signaturedata' => 'c2ln',
			'authenticatordata' => 'YXV0aA',
			'userHandle' => 'dXNlcg',
		]);

		$pi->validateCheckWebAuthn('alice', 'tx-w', $signResponse, 'https://x');

		self::assertSame('dXNlcg', $pi->lastRequest()['params']['userHandle']);
	}

	public function testValidateCheckWebAuthnReturnsNullOnInvalidJson(): void
	{
		$pi = $this->client();
		$result = $pi->validateCheckWebAuthn('alice', 'tx-w', 'not-json', 'https://x');

		self::assertNull($result);
		self::assertCount(0, $pi->captured);
	}

	public function testValidateCheckCompletePasskeyRegistrationBuildsParams(): void
	{
		$pi = $this->client();
		$registration = json_encode([
			'credential_id' => 'cred',
			'clientDataJSON' => 'cdj',
			'attestationObject' => 'att',
			'authenticatorAttachment' => 'platform',
			'rawId' => 'raw',
		]);

		$pi->validateCheckCompletePasskeyRegistration('tx', 'SER1', 'alice', $registration, 'https://x');

		$req = $pi->lastRequest();
		self::assertSame('tx', $req['params']['transaction_id']);
		self::assertSame('SER1', $req['params']['serial']);
		self::assertSame('alice', $req['params']['user']);
		self::assertSame('passkey', $req['params']['type']);
		self::assertSame('cred', $req['params']['credential_id']);
		self::assertSame('att', $req['params']['attestationObject']);
		self::assertSame('raw', $req['params']['rawId']);
	}

	public function testValidateCheckCompletePasskeyRegistrationReturnsNullOnInvalidJson(): void
	{
		$pi = $this->client();
		$result = $pi->validateCheckCompletePasskeyRegistration('tx', 'SER1', 'alice', 'not-json', 'https://x');

		self::assertNull($result);
		self::assertCount(0, $pi->captured);
	}

	public function testSetTimeoutIsAppliedToRequests(): void
	{
		$pi = $this->client();
		$pi->setTimeout('9');
		$pi->validateCheck('alice', 'pw');

		self::assertSame('9', $pi->lastRequest()['params']['timeout']);
	}

	public function testSetTimeoutIgnoresNonPositiveValues(): void
	{
		$pi = $this->client();
		$pi->setTimeout('abc');
		$pi->setTimeout('0');
		$pi->validateCheck('alice', 'pw');

		// Falls back to the default timeout of 15.
		self::assertSame('15', $pi->lastRequest()['params']['timeout']);
	}

	public function testTriggerChallengeSendsAuthorizationHeader(): void
	{
		$pi = $this->client();
		$pi->setServiceAccountName('svc');
		$pi->setServiceAccountPass('pw');
		$pi->responses['/auth'] =
			'{"result": {"status": true, "value": {"token": "JWT-TOKEN", "role": "admin"}}}';
		$pi->responses['/validate/triggerchallenge'] =
			'{"detail": {"transaction_id": "tx-tc"}, "result": {"status": true, "value": 1, "authentication": "CHALLENGE"}}';

		$response = $pi->triggerChallenge('alice');

		self::assertNotNull($response);
		$req = $pi->lastRequest();
		self::assertStringEndsWith('/validate/triggerchallenge', $req['url']);
		self::assertSame('alice', $req['params']['user']);
		self::assertContains('authorization:JWT-TOKEN', $req['headers']);
	}
}
