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

require_once __DIR__ . '/PIConstants.php';

use RecursiveArrayIterator;
use RecursiveIteratorIterator;
use function OCP\Log\logger;

/**
 * PHP client to aid develop plugins for the privacyIDEA authentication server.
 * Include the Client-Autoloader to your PHP file or simply install it using Composer.
 *
 * @author Lukas Matusiewicz <lukas.matusiewicz@netknights.it>
 */
class PrivacyIDEA
{
	/* @var string User agent name which should be forwarded to the privacyIDEA server. */
	private string $userAgent;

	/* @var string URL of the privacyIDEA server. */
	private string $serverURL;

	/* @var string User's realm. */
	private string $realm = '';

	/* @var bool Disable host verification for SSL. */
	private bool $sslVerifyHost = true;

	/* @var bool Disable peer verification for SSL. */
	private bool $sslVerifyPeer = true;

	/* @var string Account name for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint. */
	private string $serviceAccountName = '';

	/* @var string Password for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint. */
	private string $serviceAccountPass = '';

	/* @var string Realm for privacyIDEA service account. Optional to use the /validate/triggerchallenge endpoint. */
	private string $serviceAccountRealm = '';

	/* @var string Send the "client" parameter to allow using the original IP address in the privacyIDEA policies. */
	private string $forwardClientIP = '';

	/* @var string Timeout for the request. */
	private string $timeout = '5';

	/* @var bool Ignore the system-wide proxy settings and send the authentication requests directly to privacyIDEA. */
	private bool $noProxy = false;

	/**
	 * PrivacyIDEA constructor.
	 * @param $userAgent string User agent.
	 * @param $serverURL string privacyIDEA server URL.
	 */
	public function __construct(string $userAgent, string $serverURL)
	{
		$this->userAgent = $userAgent;
		$this->serverURL = $serverURL;
	}

	/**
	 * Try to authenticate the user by the /validate/check endpoint.
	 *
	 * @param string $username Username to authenticate.
	 * @param string $pass This can be the OTP, but also the PIN to trigger a token or PIN+OTP depending on the configuration of the server.
	 * @param string|null $transactionID Optional transaction ID. Used to reference a challenge that was triggered beforehand.
	 * @param array|null $headers Optional headers to forward to the server.
	 * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function validateCheck(string $username, string $pass, ?string $transactionID = null, ?array $headers = null): ?PIResponse
	{
		assert(gettype($username) === 'string');
		assert(gettype($pass) === 'string');
		if (empty($username)) {
			$this->log(DEBUG, 'Missing username for /validate/check.');
			return null;
		}
		$params = [USER => $username, PASS => $pass];
		if (!empty($transactionID)) {
			$params[TRANSACTION_ID] = $transactionID;
		}
		if (!empty($this->realm)) {
			$params[REALM] = $this->realm;
		}
		$headers = $headers ?? [''];
		$response = $this->sendRequest($params, $headers, POST, ENDPOINT_VALIDATE_CHECK);
		$ret = PIResponse::fromJSON($response, $this);
		if ($ret == null) {
			$this->log(DEBUG, 'Server did not respond.');
		}
		return $ret;
	}

	/**
	 * Trigger all challenges for the given username.
	 * This function requires a service account to be set.
	 *
	 * @param string $username Username for which the challenges should be triggered.
	 * @param array|null $headers Optional headers to forward to the server.
	 * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function triggerChallenge(string $username, ?array $headers = null): ?PIResponse
	{
		assert(gettype($username) === 'string');
		if (empty($username)) {
			$this->log(DEBUG, 'Username missing!');
			return null;
		}
		$authToken = $this->getAuthToken();
		$authTokenHeader = [AUTHORIZATION . $authToken];
		$params = [USER => $username];
		if (!empty($this->realm)) {
			$params[REALM] = $this->realm;
		}
		$headers = !empty($headers) ? array_merge($headers, $authTokenHeader) : $authTokenHeader;
		$response = $this->sendRequest($params, $headers, POST, ENDPOINT_VALIDATE_TRIGGERCHALLENGE);
		return PIResponse::fromJSON($response, $this);
	}

	/**
	 * Poll for the transaction status.
	 *
	 * @param $transactionID string Transaction ID of the triggered challenge.
	 * @param array|null $headers Optional headers to forward to the server.
	 * @return bool True if the push request has been accepted, false otherwise.
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function pollTransaction(string $transactionID, ?array $headers = null): bool
	{
		assert(gettype($transactionID) === 'string');
		if (empty($transactionID)) {
			$this->log(DEBUG, 'TransactionID missing!');
			return false;
		}
		$params = [TRANSACTION_ID => $transactionID];
		$headers = $headers ?? [''];
		$responseJSON = $this->sendRequest($params, $headers, GET, ENDPOINT_VALIDATE_POLLTRANSACTION);
		$response = json_decode($responseJSON, true);
		return $response[RESULT][VALUE] ?? false;
	}

	/**
	 * Send request to /validate/check endpoint with the data required to authenticate using WebAuthn token.
	 *
	 * @param string $username Username to authenticate.
	 * @param string $transactionID Transaction ID of the triggered challenge.
	 * @param string $webAuthnSignResponse WebAuthn sign response.
	 * @param string $origin Origin required to authenticate using WebAuthn token.
	 * @param array|null $headers Optional headers to forward to the server.
	 * @return PIResponse|null Returns PIResponse object or null if response was empty or malformed, or some parameter is missing.
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function validateCheckWebAuthn(string $username, string $transactionID, string $webAuthnSignResponse, string $origin, ?array $headers = null): ?PIResponse
	{
		assert(gettype($username) === 'string');
		assert(gettype($transactionID) === 'string');
		assert(gettype($webAuthnSignResponse) === 'string');
		assert(gettype($origin) === 'string');
		if (empty($username) || empty($transactionID) || empty($webAuthnSignResponse) || empty($origin)) {
			$this->log(DEBUG, 'validateCheckWebAuthn: parameters are incomplete!');
			return null;
		}
		$params = [USER => $username, PASS => '', TRANSACTION_ID => $transactionID];
		if (!empty($this->realm)) {
			$params[REALM] = $this->realm;
		}
		$tmp = json_decode($webAuthnSignResponse, true);
		$params[CREDENTIALID] = $tmp[CREDENTIALID];
		$params[CLIENTDATA] = $tmp[CLIENTDATA];
		$params[SIGNATUREDATA] = $tmp[SIGNATUREDATA];
		$params[AUTHENTICATORDATA] = $tmp[AUTHENTICATORDATA];
		if (!empty($tmp[USERHANDLE])) {
			$params[USERHANDLE] = $tmp[USERHANDLE];
		}
		if (!empty($tmp[ASSERTIONCLIENTEXTENSIONS])) {
			$params[ASSERTIONCLIENTEXTENSIONS] = $tmp[ASSERTIONCLIENTEXTENSIONS];
		}
		$headers = $this->mergeHeaders($origin, $headers);
		$response = $this->sendRequest($params, $headers, POST, ENDPOINT_VALIDATE_CHECK);
		return PIResponse::fromJSON($response, $this);
	}

	/**
	 * Authenticate using a passkey. If successful, the response will contain the username.
	 *
	 * @param string $transactionID TransactionID.
	 * @param string $passkeyResponse The json serialized response from the authenticator. Is the same as a webauthnSignResponse.
	 * @param string $origin Origin of the passkeyResponse, usually gotten from a browser.
	 * @param array|null $headers Optional headers for the request.
	 * @return PIResponse|null PIResponse or null if error.
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function validateCheckPasskey(string $transactionID, string $passkeyResponse, string $origin, ?array $headers = null): ?PIResponse
	{
		assert(gettype($transactionID) === 'string');
		assert(gettype($passkeyResponse) === 'string');
		assert(gettype($origin) === 'string');
		if (empty($transactionID) || empty($passkeyResponse) || empty($origin)) {
			$this->log(DEBUG, 'validateCheckPasskey: parameters are invalid or incomplete!');
			return null;
		}
		$passkeyResponseParams = json_decode($passkeyResponse, true);
		if (!is_array($passkeyResponseParams)) {
			$this->log(DEBUG, 'Invalid passkey response for validateCheckPasskey. Expected an array.');
			return null;
		}
		$params = [
			TRANSACTION_ID => $transactionID,
			CREDENTIAL_ID => $passkeyResponseParams[CREDENTIAL_ID],
			CLIENTDATAJSON => $passkeyResponseParams[CLIENTDATAJSON],
			SIGNATURE => $passkeyResponseParams[SIGNATURE],
			AUTHENTICATOR_DATA => $passkeyResponseParams[AUTHENTICATOR_DATA]
		];
		if (!empty($passkeyResponseParams[USERHANDLE])) {
			$params[USERHANDLE] = $passkeyResponseParams[USERHANDLE];
		}
		if (!empty($passkeyResponseParams[ASSERTIONCLIENTEXTENSIONS])) {
			$params[ASSERTIONCLIENTEXTENSIONS] = $passkeyResponseParams[ASSERTIONCLIENTEXTENSIONS];
		}
		if (!empty($this->realm)) {
			$params[REALM] = $this->realm;
		}
		$headers = $this->mergeHeaders($origin, $headers);
		$response = $this->sendRequest($params, $headers, POST, ENDPOINT_VALIDATE_CHECK);
		return PIResponse::fromJSON($response, $this);
	}

	/**
	 * Complete a passkey registration via the endpoint /validate/check. This is the second step of the registration process that was
	 * triggered by the enroll_via_multichallenge setting in privacyIDEA.
	 *
	 * @param string $transactionID TransactionID.
	 * @param string $serial Serial of the token.
	 * @param string $username Username.
	 * @param string $registrationResponse The registration data from the authenticator in json format.
	 * @param string $origin Origin of the registrationResponse, usually gotten from a browser.
	 * @param array|null $headers Optional headers for the request.
	 * @return PIResponse|null PIResponse or null if error
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function validateCheckCompletePasskeyRegistration(string $transactionID, string $serial, string $username, string $registrationResponse, string $origin, ?array $headers = null): ?PIResponse
	{
		assert(gettype($transactionID) === 'string');
		assert(gettype($serial) === 'string');
		assert(gettype($username) === 'string');
		assert(gettype($registrationResponse) === 'string');
		assert(gettype($origin) === 'string');
		if (empty($transactionID) || empty($serial) || empty($username) || empty($registrationResponse) || empty($origin)) {
			$this->log(DEBUG, 'validateCheckCompletePasskeyRegistration: parameters are incomplete!');
			return null;
		}
		try {
			$registrationResponseParams = json_decode($registrationResponse, true);
		} catch (\Exception $e) {
			$this->log(DEBUG, 'Invalid registration response for validateCheckCompletePasskeyRegistration: ' . $e->getMessage());
			return null;
		}
		$params = [
			TRANSACTION_ID => $transactionID,
			SERIAL => $serial,
			USER => $username,
			TYPE => PASSKEY,
			CREDENTIAL_ID => $registrationResponseParams[CREDENTIAL_ID],
			CLIENTDATAJSON => $registrationResponseParams[CLIENTDATAJSON],
			ATTESTATIONOBJECT => $registrationResponseParams[ATTESTATIONOBJECT],
			AUTHENTICATORATTACHMENT => $registrationResponseParams[AUTHENTICATORATTACHMENT],
			RAWID => $registrationResponseParams[RAWID]
		];
		if (!empty($this->realm)) {
			$params[REALM] = $this->realm;
		}
		$headers = $this->mergeHeaders($origin, $headers);
		$response = $this->sendRequest($params, $headers, POST, ENDPOINT_VALIDATE_CHECK);
		return PIResponse::fromJSON($response, $this);
	}

	/**
	 * Cancel an ongoing enrollment via multichallenge. This is done by sending a request to the /validate/check endpoint.
	 * This request only contains the transaction ID and the cancel_enrollment parameter set to true.
	 *
	 * @param string $transactionID TransactionID of the ongoing enrollment.
	 * @throws PIBadRequestException
	 */
	public function validateCheckCancelEnrollment(string $transactionID, ?array $headers = null): ?PIResponse
	{
		assert(gettype($transactionID) === 'string');
		if (empty($transactionID)) {
			$this->log(DEBUG, 'validateCheckCancelEnrollment: transactionID is missing!');
			return null;
		}
		$params = [TRANSACTION_ID => $transactionID, CANCEL_ENROLLMENT => 'true'];
		if (!empty($this->realm)) {
			$params[REALM] = $this->realm;
		}
		$headers = $headers ?? [''];
		$response = $this->sendRequest($params, $headers, POST, ENDPOINT_VALIDATE_CHECK);
		return PIResponse::fromJSON($response, $this);
	}

	/**
	 * Check if name and pass of service account are set.
	 * @return bool
	 */
	public function serviceAccountAvailable(): bool
	{
		return (!empty($this->serviceAccountName) && !empty($this->serviceAccountPass));
	}

	/**
	 * Retrieves the auth token from the server using the service account. An auth token is required for some requests to the privacyIDEA.
	 *
	 * @return string Auth token or empty string if the response did not contain a token or no service account is configured.
	 * @throws PIBadRequestException If an error occurs during the request.
	 */
	public function getAuthToken(): string
	{
		if (!$this->serviceAccountAvailable()) {
			$this->log(ERROR, 'Cannot retrieve auth token without service account!');
			return '';
		}
		$params = [USERNAME => $this->serviceAccountName, PASSWORD => $this->serviceAccountPass];
		if (!empty($this->serviceAccountRealm)) {
			$params[REALM] = $this->serviceAccountRealm;
		}
		$response = json_decode($this->sendRequest($params, [''], POST, ENDPOINT_AUTH), true);
		if (!empty($response[RESULT][VALUE][TOKEN])) {
			if ($this->findRecursive($response, ROLE) != ADMIN) {
				$this->log(DEBUG, 'Auth token was of a user without admin role.');
				return '';
			}
			return $response[RESULT][VALUE][TOKEN];
		}
		$this->log(DEBUG, '/auth response did not contain the auth token.');
		return '';
	}

	/**
	 * Find key recursively in array.
	 *
	 * @param array $haystack The array which will be searched.
	 * @param string $needle Search string.
	 * @return mixed Result of key search.
	 */
	public function findRecursive(array $haystack, string $needle): mixed
	{
		assert(is_array($haystack));
		assert(is_string($needle));
		$iterator = new RecursiveArrayIterator($haystack);
		$recursive = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::SELF_FIRST);
		foreach ($recursive as $key => $value) {
			if ($key === $needle) {
				return $value;
			}
		}
		return false;
	}

	/**
	 * Send requests to the endpoint with specified parameters and headers.
	 *
	 * @param $params array Request parameters.
	 * @param $headers array Headers to forward.
	 * @param $httpMethod string GET or POST.
	 * @param $endpoint string Endpoint of the privacyIDEA API (e.g. /validate/check).
	 * @return string Returns a string with the server response.
	 * @throws PIBadRequestException If an error occurs.
	 */
	private function sendRequest(array $params, array $headers, string $httpMethod, string $endpoint): string
	{
		assert(gettype($params) === 'array');
		assert(gettype($headers) === 'array');
		assert(gettype($httpMethod) === 'string');
		assert(gettype($endpoint) === 'string');
		if (!empty($this->forwardClientIP)) {
			$params[CLIENT] = $this->forwardClientIP;
			$this->log(DEBUG, 'Forwarding Client IP: ' . $this->forwardClientIP);
		}
		if ($this->noProxy === true) {
			$this->log(DEBUG, 'Ignoring proxy settings.');
			$params[PROXY] = [HTTPS => '', HTTP => ''];
		}
		$params[TIMEOUT] = $this->timeout;
		$this->log(DEBUG, 'Sending ' . http_build_query($params, '', ', ') . ' to ' . $endpoint);
		$completeUrl = $this->serverURL . $endpoint;
		$curlInstance = curl_init();
		curl_setopt($curlInstance, CURLOPT_URL, $completeUrl);
		curl_setopt($curlInstance, CURLOPT_HEADER, true);
		if ($headers) {
			curl_setopt($curlInstance, CURLOPT_HTTPHEADER, $headers);
		}
		curl_setopt($curlInstance, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curlInstance, CURLOPT_USERAGENT, $this->userAgent);
		if ($httpMethod === POST) {
			curl_setopt($curlInstance, CURLOPT_POST, true);
			curl_setopt($curlInstance, CURLOPT_POSTFIELDS, $params);
		} elseif ($httpMethod === PUT || $httpMethod === DELETE) {
			curl_setopt($curlInstance, CURLOPT_CUSTOMREQUEST, $httpMethod);
			curl_setopt($curlInstance, CURLOPT_POSTFIELDS, $params);
		} elseif ($httpMethod === GET) {
			$paramsStr = !empty($params) ? '?' . http_build_query($params) : '';
			curl_setopt($curlInstance, CURLOPT_URL, $completeUrl . $paramsStr);
		}
		curl_setopt($curlInstance, CURLOPT_SSL_VERIFYHOST, $this->sslVerifyHost ? 2 : 0);
		curl_setopt($curlInstance, CURLOPT_SSL_VERIFYPEER, $this->sslVerifyPeer ? 2 : 0);
		$response = curl_exec($curlInstance);
		if (!$response) {
			$curlErrno = curl_errno($curlInstance);
			$this->log(ERROR, 'Bad request: ' . curl_error($curlInstance) . ' errno: ' . $curlErrno);
			throw new PIBadRequestException('Unable to reach the authentication server (' . $curlErrno . ')');
		}
		$headerSize = curl_getinfo($curlInstance, CURLINFO_HEADER_SIZE);
		$ret = substr($response, $headerSize);
		curl_close($curlInstance);
		if ($endpoint != ENDPOINT_AUTH) {
			$retJson = json_decode($ret, true);
			$this->log(DEBUG, $endpoint . ' returned ' . json_encode($retJson, JSON_PRETTY_PRINT));
		}
		return $ret;
	}

	/**
	 * Merge the origin with the given headers.
	 *
	 * @param string $origin
	 * @param array|null $headers
	 * @return array|string[]
	 */
	public function mergeHeaders(string $origin, ?array $headers): array
	{
		$originHeader = [ORIGIN . $origin];
		return array_merge((array)$headers, $originHeader);
	}

	/**
	 * Log a message with the given log level.
	 *
	 * @param $level
	 * @param $message
	 */
	public function log($level, $message): void
	{
		if ($level === DEBUG) {
			logger(APP_ID_PRIVACYIDEA)->debug($message);
		}
		if ($level === INFO) {
			logger(APP_ID_PRIVACYIDEA)->info($message);
		}
		if ($level === ERROR) {
			logger(APP_ID_PRIVACYIDEA)->error($message);
		}
	}

	// Setters

	/**
	 * @param string $realm User's realm.
	 * @return void
	 */
	public function setRealm(string $realm): void
	{
		$this->realm = $realm;
	}

	/**
	 * @param bool $sslVerifyHost Disable host verification for SSL.
	 * @return void
	 */
	public function setSSLVerifyHost(bool $sslVerifyHost): void
	{
		$this->sslVerifyHost = $sslVerifyHost;
	}

	/**
	 * @param bool $sslVerifyPeer Disable peer verification for SSL.
	 * @return void
	 */
	public function setSSLVerifyPeer(bool $sslVerifyPeer): void
	{
		$this->sslVerifyPeer = $sslVerifyPeer;
	}

	/**
	 * @param string $serviceAccountName Account name for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint.
	 * @return void
	 */
	public function setServiceAccountName(string $serviceAccountName): void
	{
		$this->serviceAccountName = $serviceAccountName;
	}

	/**
	 * @param string $serviceAccountPass Password for privacyIDEA service account. Required to use the /validate/triggerchallenge endpoint.
	 * @return void
	 */
	public function setServiceAccountPass(string $serviceAccountPass): void
	{
		$this->serviceAccountPass = $serviceAccountPass;
	}

	/**
	 * @param string $serviceAccountRealm Realm for privacyIDEA service account. Optional to use the /validate/triggerchallenge endpoint.
	 * @return void
	 */
	public function setServiceAccountRealm(string $serviceAccountRealm): void
	{
		$this->serviceAccountRealm = $serviceAccountRealm;
	}

	/**
	 * @param bool $clientIP Send the "client" parameter to allow using the original IP address in the privacyIDEA policies.
	 * @return void
	 */
	public function setForwardClientIP(bool $clientIP): void
	{
		$this->forwardClientIP = $clientIP;
	}

	/**
	 * @param bool $noProxy Ignore the system-wide proxy settings and send the authentication requests directly to privacyIDEA.
	 * @return void
	 */
	public function setNoProxy(bool $noProxy): void
	{
		$this->noProxy = $noProxy;
	}
}
