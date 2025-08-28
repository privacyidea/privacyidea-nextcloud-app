<?php
/*
 * Copyright 2024 NetKnights GmbH - lukas.matusiewicz@netknights.it
 * <p>
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3;
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace OCA\PrivacyIDEA\PIClient;

class PIResponse
{
	/* @var string Combined messages of all triggered token. */
	private string $messages = '';

	/* @var string Message from the response. Should be shown to the user. */
	private string $message = '';

	/* @var string Token's serial. */
	private string $serial = '';

	/* @var string Transaction ID is used to reference the challenges contained in this response in later requests. */
	private string $transactionID = '';

	/* @var string Preferred mode in which client should work after triggering challenges. */
	private string $preferredClientMode = '';

	/* @var string Raw response in JSON format. */
	private string $raw = '';

	/* @var array Array of PIChallenge objects representing the triggered token challenges. */
	private array $multiChallenge = [];

	/* @var bool Status indicates if the request was processed successfully by the server. */
	private bool $status = false;

	/* @var bool Value is true if the authentication was successful. */
	private bool $value = false;

	/* @var string Authentication Status. */
	private string $authenticationStatus = '';

	/* @var string Passkey challenge in JSON string. */
	private string $passkeyChallenge = '';

	/* @var string Passkey registration. */
	private string $passkeyRegistration = '';

	/* @var string Passkey registration serial. */
	private string $passkeyRegistrationSerial = '';

	/* @var string Username returned from the privacyIDEA server. */
	private string $username = '';

	/* @var string If an error occurred, the error code will be set here. */
	private string $errorCode = '';

	/* @var string If an error occurred, the error message will be set here. */
	private string $errorMessage = '';

	/**
	 * Create a PIResponse object from the JSON response of the server.
	 *
	 * @param string $json Server response in JSON format.
	 * @param PrivacyIDEA $privacyIDEA PrivacyIDEA object.
	 * @return PIResponse|null Returns the PIResponse object or null if the response of the server is empty or malformed.
	 */
	public static function fromJSON(string $json, PrivacyIDEA $privacyIDEA): ?PIResponse
	{
		assert(gettype($json) === 'string');

		if ($json == null || $json == '') {
			$privacyIDEA->log('error', 'Response from the server is empty.');
			return null;
		}

		$ret = new PIResponse();
		$map = json_decode($json, true);
		if ($map == null) {
			$privacyIDEA->log('error', "Response from the server is malformed:\n" . $json);
			return null;
		}
		$ret->raw = $json;

		// If value is not present, an error occurred
		if (!isset($map['result']['value'])) {
			$ret->errorCode = $map['result']['error']['code'];
			$ret->errorMessage = $map['result']['error']['message'];
			return $ret;
		}

		if (isset($map['detail']['messages'])) {
			$ret->messages = implode(', ', array_unique($map['detail']['messages'])) ?: '';
		}
		if (isset($map['detail']['message'])) {
			$ret->message = $map['detail']['message'];
		}
		if (isset($map['detail']['username'])) {
			$ret->username = $map['detail']['username'];
		}
		if (isset($map['detail']['serial'])) {
			$ret->serial = $map['detail']['serial'];
		}
		if (isset($map['detail']['transaction_id'])) {
			$ret->transactionID = $map['detail']['transaction_id'];
		}
		if (isset($map['detail']['preferred_client_mode'])) {
			$pref = $map['detail']['preferred_client_mode'];
			if ($pref === 'poll') {
				$ret->preferredClientMode = 'push';
			} elseif ($pref === 'interactive') {
				$ret->preferredClientMode = 'otp';
			} else {
				$ret->preferredClientMode = $map['detail']['preferred_client_mode'];
			}
		}
		if (!empty($map['detail']['passkey'])) {
			$ret->passkeyChallenge = json_encode($map['detail']['passkey']);
			// The passkey challenge can contain a transaction ID, use that if none was set prior.
			// This happens if the passkey challenge was requested via /validate/initialize.
			if (empty($ret->transactionID)) {
				$ret->transactionID = $map['detail']['passkey']['transaction_id'];
			}
		}

		// Check if the authentication status is legit
		$r = null;
		if (!empty($map['result']['authentication'])) {
			$r = $map['result']['authentication'];
		}
		if ($r === AuthenticationStatus::CHALLENGE) {
			$ret->authenticationStatus = AuthenticationStatus::CHALLENGE;
		} elseif ($r === AuthenticationStatus::ACCEPT) {
			$ret->authenticationStatus = AuthenticationStatus::ACCEPT;
		} elseif ($r === AuthenticationStatus::REJECT) {
			$ret->authenticationStatus = AuthenticationStatus::REJECT;
		} else {
			$privacyIDEA->log('debug', 'Unknown authentication status.');
			$ret->authenticationStatus = AuthenticationStatus::NONE;
		}
		$ret->status = $map['result']['status'] ?: false;
		$ret->value = $map['result']['value'] ?: false;

		// Add any challenges to multiChallenge
		if (isset($map['detail']['multi_challenge'])) {
			$mc = $map['detail']['multi_challenge'];
			foreach ($mc as $challenge) {
				$tmp = new PIChallenge();
				$tmp->transactionID = $challenge['transaction_id'];
				if (isset($challenge['message'])) {
					$tmp->message = $challenge['message'];
				}
				$tmp->serial = $challenge['serial'];
				if (isset($challenge['type'])) {
					$tmp->type = $challenge['type'];
				}
				if (isset($challenge['image'])) {
					$tmp->image = $challenge['image'];
				}
				if (isset($challenge['link'])) {
					$tmp->enrollmentLink = $challenge['link'];
				}
				if (isset($challenge['attributes'])) {
					$tmp->attributes = $challenge['attributes'];
				}
				if (isset($challenge['client_mode'])) {
					$tmp->clientMode = $challenge['client_mode'];
				}
				if ($tmp->type === 'webauthn') {
					$tmp->webAuthnSignRequest = json_encode($challenge['attributes']['webAuthnSignRequest']);
				}
				if ($tmp->type === 'passkey') {
					$ret->passkeyChallenge = json_encode($challenge);
				}
				if (!empty($challenge['passkey_registration'])) {
					$ret->passkeyRegistration = json_encode($challenge['passkey_registration']);
					$ret->passkeyRegistrationSerial = $challenge['serial'];
				}

				$ret->multiChallenge[] = $tmp;
			}
		}
		return $ret;
	}

	/**
	 * Check if the authentication was successful.
	 * This is true if the authentication status is ACCEPT or if there are no multi-challenges.
	 * If there are multi-challenges, the value must be true and no multi-challenge must be present.
	 *
	 * @return bool True if the authentication was successful, false otherwise.
	 */
	public function isAuthenticationSuccessful(): bool
	{
		if ($this->authenticationStatus == AuthenticationStatus::ACCEPT && empty($this->multiChallenge)) {
			return true;
		} else {
			return $this->value && (empty($this->multiChallenge));
		}
	}

	/**
	 * Get an array with all triggered token types.
	 * @return array
	 */
	public function getTriggeredTokenTypes(): array
	{
		$ret = [];
		foreach ($this->multiChallenge as $challenge) {
			$ret[] = $challenge->type;
		}
		return array_unique($ret);
	}

	/**
	 * Get the message of any token that is not Push or WebAuthn. Those are OTP tokens requiring an input field.
	 * @return string
	 */
	public function getOtpMessage(): string
	{
		foreach ($this->multiChallenge as $challenge) {
			if ($challenge->type !== 'push' && $challenge->type !== 'webauthn') {
				return $challenge->message;
			}
		}
		return '';
	}

	/**
	 * Get the Push token message if any were triggered.
	 * @return string
	 */
	public function getPushMessage(): string
	{
		foreach ($this->multiChallenge as $challenge) {
			if ($challenge->type === 'push') {
				return $challenge->message;
			}
		}
		return '';
	}

	/**
	 * Get the Passkey message if any were triggered..
	 * @return string
	 */
	public function getPasskeyMessage(): string
	{
		foreach ($this->multiChallenge as $challenge) {
			if ($challenge->type === 'passkey') {
				return $challenge->message;
			}
		}
		return '';
	}

	/**
	 * Get the Passkey challenge in JSON format.
	 * This is used to create a passkey request.
	 *
	 * @return string Passkey challenge.
	 */
	public function getPasskeyChallenge(): string
	{
		return $this->passkeyChallenge;
	}

	/**
	 * Get the Passkey registration in JSON format.
	 * This is used to create a passkey registration request.
	 *
	 * @return string Passkey registration.
	 */
	public function getPasskeyRegistration(): string
	{
		return $this->passkeyRegistration;
	}

	/**
	 * Get the Passkey registration serial.
	 * This is used to identify the passkey registration.
	 *
	 * @return string Passkey registration serial.
	 */
	public function getPasskeyRegistrationSerial(): string
	{
		return $this->passkeyRegistrationSerial;
	}

	/**
	 * @return string Combined messages of all triggered token.
	 */
	public function getMessages(): string
	{
		return $this->messages;
	}

	/**
	 * @return string Token's serial.
	 */
	public function getSerial(): string
	{
		return $this->serial;
	}

	/**
	 * @return string Message from the response. Should be shown to the user.
	 */
	public function getMessage(): string
	{
		return $this->message;
	}

	/**
	 * @return string Transaction ID is used to reference the challenges contained in this response in later requests.
	 */
	public function getTransactionID(): string
	{
		return $this->transactionID;
	}

	/**
	 * @return string Preferred mode in which client should work after triggering challenges.
	 */
	public function getPreferredClientMode(): string
	{
		return $this->preferredClientMode;
	}

	/**
	 * @return string Raw response in JSON format.
	 */
	public function getRawResponse(): string
	{
		return $this->raw;
	}

	/**
	 * Get the WebAuthnSignRequest for any triggered WebAuthn token.
	 * @return string WebAuthnSignRequest or empty string if no WebAuthn token was triggered.
	 */
	public function getWebauthnSignRequest(): string
	{
		$arr = [];
		$webauthn = '';
		foreach ($this->multiChallenge as $challenge) {
			if ($challenge->type === 'webauthn') {
				$t = json_decode($challenge->webAuthnSignRequest);
				if (empty($webauthn)) {
					$webauthn = $t;
				}
				$arr[] = $challenge->attributes['webAuthnSignRequest']['allowCredentials'][0];
			}
		}
		if (empty($webauthn)) {
			return '';
		} else {
			$webauthn->allowCredentials = $arr;
			return json_encode($webauthn);
		}
	}

	/**
	 * Get the WebAuthn token message if any were triggered.
	 * @return string
	 */
	public function getWebauthnMessage(): string
	{
		foreach ($this->multiChallenge as $challenge) {
			if ($challenge->type === 'webauthn') {
				return $challenge->message;
			}
		}
		return '';
	}

	/**
	 * @return array Array of PIChallenge objects representing the triggered token challenges.
	 */
	public function getMultiChallenge(): array
	{
		return $this->multiChallenge;
	}

	/**
	 * @return bool Status indicates if the request was processed successfully by the server.
	 */
	public function getStatus(): bool
	{
		return $this->status;
	}

	/**
	 * @return bool Value is true if the authentication was successful.
	 */
	public function getValue(): bool
	{
		return $this->value;
	}

	/**
	 * @return string Authentication Status.
	 */
	public function getAuthenticationStatus(): string
	{
		return $this->authenticationStatus;
	}

	/**
	 * @return string If an error occurred, the error code will be set here.
	 */
	public function getErrorCode(): string
	{
		return $this->errorCode;
	}

	/**
	 * @return string If an error occurred, the error message will be set here.
	 */
	public function getErrorMessage(): string
	{
		return $this->errorMessage;
	}
}
