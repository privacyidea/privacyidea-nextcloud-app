<?php

/*
 * Copyright 2024 NetKnights GmbH
 *
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.
 */

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Tests\Unit\PIClient;

use OCA\PrivacyIDEA\PIClient\AuthenticationStatus;
use OCA\PrivacyIDEA\PIClient\PIResponse;
use OCA\PrivacyIDEA\PIClient\PrivacyIDEA;
use PHPUnit\Framework\TestCase;

/**
 * Tests for {@see PIResponse::fromJSON()}.
 *
 * The fixtures are real /validate/check response bodies captured in
 * validate-doc/*.md (envelope fields id/jsonrpc/signature/... stripped, as
 * documented there). PIResponse::fromJSON needs a PrivacyIDEA only for
 * logging, so a mock is passed.
 */
class PIResponseTest extends TestCase
{
	private PrivacyIDEA $piMock;

	protected function setUp(): void
	{
		$this->piMock = $this->createMock(PrivacyIDEA::class);
	}

	private function parse(string $json): ?PIResponse
	{
		return PIResponse::fromJSON($json, $this->piMock);
	}

	public function testEmptyResponseReturnsNull(): void
	{
		self::assertNull($this->parse(''));
	}

	public function testMalformedJsonReturnsNull(): void
	{
		self::assertNull($this->parse('this is not json'));
	}

	public function testHotpChallengeResponse(): void
	{
		$json = <<<'JSON'
		{
		  "detail": {
		    "client_mode": "interactive",
		    "message": "please enter otp: ",
		    "messages": ["please enter otp: "],
		    "multi_challenge": [
		      {
		        "client_mode": "interactive",
		        "message": "please enter otp: ",
		        "serial": "hotp1",
		        "transaction_id": "08954727052769857579",
		        "type": "hotp"
		      }
		    ],
		    "preferred_client_mode": "interactive",
		    "serial": "hotp1",
		    "transaction_id": "08954727052769857579",
		    "transaction_ids": ["08954727052769857579"],
		    "type": "hotp"
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame(AuthenticationStatus::CHALLENGE, $r->getAuthenticationStatus());
		self::assertTrue($r->getStatus());
		self::assertFalse($r->getValue());
		self::assertSame('08954727052769857579', $r->getTransactionID());
		self::assertSame('hotp1', $r->getSerial());
		self::assertSame('please enter otp: ', $r->getMessage());
		self::assertSame(['hotp'], $r->getTriggeredTokenTypes());
		self::assertSame('please enter otp: ', $r->getOtpMessage());
		// preferred_client_mode "interactive" is normalized to "otp".
		self::assertSame('otp', $r->getPreferredClientMode());
		self::assertFalse($r->isAuthenticationSuccessful());
		self::assertCount(1, $r->getMultiChallenge());
	}

	public function testAcceptResponseIsSuccessful(): void
	{
		$json = <<<'JSON'
		{
		  "detail": {"message": "Found matching challenge", "serial": "hotp1"},
		  "result": {"authentication": "ACCEPT", "status": true, "value": true}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame(AuthenticationStatus::ACCEPT, $r->getAuthenticationStatus());
		self::assertTrue($r->getValue());
		self::assertTrue($r->isAuthenticationSuccessful());
		self::assertSame('hotp1', $r->getSerial());
	}

	public function testErrorResponseExtractsCodeAndMessage(): void
	{
		// Error envelope: result.value absent -> error path.
		$json = <<<'JSON'
		{
		  "detail": null,
		  "result": {
		    "status": false,
		    "error": {"code": 905, "message": "ERR905: Missing parameter: transaction_id"}
		  }
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame('905', (string)$r->getErrorCode());
		self::assertSame('ERR905: Missing parameter: transaction_id', $r->getErrorMessage());
		self::assertFalse($r->isAuthenticationSuccessful());
	}

	public function testPushPreferredModeMapsToPush(): void
	{
		// preferred_client_mode "poll" -> "push"; type push is detected.
		$json = <<<'JSON'
		{
		  "detail": {
		    "client_mode": "poll",
		    "message": "Please confirm the authentication on your mobile device!",
		    "messages": ["Please confirm the authentication on your mobile device!"],
		    "multi_challenge": [
		      {
		        "client_mode": "poll",
		        "message": "Please confirm the authentication on your mobile device!",
		        "serial": "PIPU0001",
		        "transaction_id": "16786464",
		        "type": "push"
		      }
		    ],
		    "preferred_client_mode": "poll",
		    "serial": "PIPU0001",
		    "transaction_id": "16786464",
		    "type": "push"
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame('push', $r->getPreferredClientMode());
		self::assertTrue($r->isPushOrSmartphoneContainerAvailable());
		self::assertSame(
			'Please confirm the authentication on your mobile device!',
			$r->getPushOrSmartphoneContainerMessage()
		);
		// getOtpMessage skips push challenges.
		self::assertSame('', $r->getOtpMessage());
	}

	public function testInteractivePushCodeToPhoneIsNotOfferedAsPollablePush(): void
	{
		// A push_code_to_phone challenge is client_mode "interactive" -> answered
		// via the OTP field, so the poll-based Push button must not be offered.
		$json = <<<'JSON'
		{
		  "detail": {
		    "attributes": {"hideResponseInput": false},
		    "client_mode": "interactive",
		    "message": "Please enter the code displayed on your smartphone.",
		    "messages": ["Please enter the code displayed on your smartphone."],
		    "multi_challenge": [
		      {
		        "attributes": {"hideResponseInput": false},
		        "client_mode": "interactive",
		        "message": "Please enter the code displayed on your smartphone.",
		        "serial": "PIPU001",
		        "transaction_id": "00110530786071310297",
		        "type": "push"
		      }
		    ],
		    "preferred_client_mode": "interactive",
		    "serial": "PIPU001",
		    "transaction_id": "00110530786071310297",
		    "type": "push"
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame(['push'], $r->getTriggeredTokenTypes());
		// interactive -> normalized to "otp", not "push".
		self::assertSame('otp', $r->getPreferredClientMode());
		// An interactive push (code_to_phone) is answered via the OTP field, not
		// by polling, so it must not be reported as a pollable push offering.
		self::assertFalse($r->isPushOrSmartphoneContainerAvailable());
		self::assertSame('00110530786071310297', $r->getTransactionID());
	}

	public function testWebauthnSignRequestAssembled(): void
	{
		$json = <<<'JSON'
		{
		  "detail": {
		    "message": "Please confirm with your WebAuthn token",
		    "multi_challenge": [
		      {
		        "type": "webauthn",
		        "serial": "WAN0001",
		        "transaction_id": "99887766",
		        "message": "Please confirm with your WebAuthn token",
		        "client_mode": "webauthn",
		        "attributes": {
		          "webAuthnSignRequest": {
		            "allowCredentials": [
		              {"id": "cred-id-1", "type": "public-key", "transports": ["usb", "nfc"]}
		            ],
		            "challenge": "d2ViYXV0aG4",
		            "rpId": "cool.nils",
		            "timeout": 60000,
		            "userVerification": "preferred"
		          }
		        }
		      }
		    ],
		    "transaction_id": "99887766",
		    "type": "webauthn"
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertContains('webauthn', $r->getTriggeredTokenTypes());
		self::assertSame('Please confirm with your WebAuthn token', $r->getWebauthnMessage());

		$signRequest = json_decode($r->getWebauthnSignRequest(), true);
		self::assertIsArray($signRequest);
		self::assertSame('cool.nils', $signRequest['rpId']);
		self::assertSame('d2ViYXV0aG4', $signRequest['challenge']);
		self::assertArrayHasKey('allowCredentials', $signRequest);
		self::assertSame('cred-id-1', $signRequest['allowCredentials'][0]['id']);
	}

	public function testWebauthnSignRequestOmitsMissingAllowCredentials(): void
	{
		// A WebAuthn challenge without allowCredentials[0] must not put a null
		// into the assembled allowCredentials list; the browser would otherwise
		// throw on credential.id and drop back to OTP.
		$json = <<<'JSON'
		{
		  "detail": {
		    "multi_challenge": [
		      {
		        "type": "webauthn",
		        "serial": "WAN0001",
		        "transaction_id": "tx",
		        "message": "confirm",
		        "client_mode": "webauthn",
		        "attributes": {
		          "webAuthnSignRequest": {"challenge": "chal", "rpId": "rp", "timeout": 60000}
		        }
		      }
		    ],
		    "transaction_id": "tx",
		    "type": "webauthn"
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		$signRequest = json_decode($r->getWebauthnSignRequest(), true);
		self::assertIsArray($signRequest);
		self::assertSame([], $signRequest['allowCredentials']);
		self::assertNotContains(null, $signRequest['allowCredentials']);
	}

	public function testPasskeyChallengeExtractedFromDetail(): void
	{
		// /validate/initialize-style body: detail.passkey carries the challenge,
		// and the transaction_id is taken from it when absent at top level.
		$json = <<<'JSON'
		{
		  "detail": {
		    "passkey": {
		      "challenge": "cGtjaGFsbGVuZ2U",
		      "message": "Please authenticate with your passkey",
		      "rpId": "cool.nils",
		      "transaction_id": "12345678901234567890",
		      "user_verification": "preferred"
		    }
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame('12345678901234567890', $r->getTransactionID());
		$challenge = json_decode($r->getPasskeyChallenge(), true);
		self::assertIsArray($challenge);
		self::assertSame('cool.nils', $challenge['rpId']);
		self::assertSame('cGtjaGFsbGVuZ2U', $challenge['challenge']);
	}

	public function testMalformedMessagesFieldDoesNotThrow(): void
	{
		// A non-array detail.messages must not blow up array_unique; fromJSON is
		// contracted to parse any server response gracefully and here yields an
		// empty messages string while still reading the other fields.
		$json = <<<'JSON'
		{
		  "detail": {"messages": "not an array", "message": "please enter otp", "transaction_id": "tx-1"},
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertSame('', $r->getMessages());
		self::assertSame('please enter otp', $r->getMessage());
		self::assertSame('tx-1', $r->getTransactionID());
	}

	public function testEnrollViaMultichallengeFlags(): void
	{
		$json = <<<'JSON'
		{
		  "detail": {
		    "enroll_via_multichallenge": true,
		    "enroll_via_multichallenge_optional": true,
		    "client_mode": "interactive",
		    "message": "Please scan the QR code",
		    "messages": ["Please scan the QR code"],
		    "multi_challenge": [
		      {
		        "client_mode": "interactive",
		        "image": "data:image/png;base64,AAAA",
		        "link": "otpauth://hotp/foo",
		        "message": "Please scan the QR code",
		        "serial": "OATH0001",
		        "transaction_id": "5555",
		        "type": "hotp"
		      }
		    ],
		    "serial": "OATH0001",
		    "transaction_id": "5555",
		    "type": "hotp"
		  },
		  "result": {"authentication": "CHALLENGE", "status": true, "value": false}
		}
		JSON;
		$r = $this->parse($json);

		self::assertNotNull($r);
		self::assertTrue($r->isEnrollViaMultichallenge());
		self::assertTrue($r->isEnrollViaMultichallengeOptional());
		$challenges = $r->getMultiChallenge();
		self::assertSame('data:image/png;base64,AAAA', $challenges[0]->image);
		self::assertSame('otpauth://hotp/foo', $challenges[0]->enrollmentLink);
	}
}
