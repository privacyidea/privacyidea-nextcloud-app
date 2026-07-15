<?php

namespace OCA\PrivacyIDEA\Provider;

use Exception;
use OCA\PrivacyIDEA\PIClient\AuthenticationStatus;
use OCA\PrivacyIDEA\PIClient\PIBadRequestException;
use OCA\PrivacyIDEA\PIClient\PIResponse;
use OCA\PrivacyIDEA\PIClient\PrivacyIDEA;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorException;
use OCP\IAppConfig;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\Template;
use Psr\Log\LoggerInterface;

class PrivacyIDEAProvider implements IProvider
{
	/** @var IAppConfig */
	private IAppConfig $appConfig;
	/** @var LoggerInterface */
	private LoggerInterface $logger;
	/** @var IRequest */
	private IRequest $request;
	/** @var IGroupManager */
	private IGroupManager $groupManager;
	/** @var IL10N */
	private IL10N $trans;
	/** @var ISession */
	private ISession $session;
	/** @var PrivacyIDEAFactory */
	private PrivacyIDEAFactory $piFactory;
	/** @var PrivacyIDEA|null */
	private ?PrivacyIDEA $pi = null;

	/**
	 * PrivacyIDEAProvider constructor.
	 *
	 * @param IAppConfig $appConfig
	 * @param LoggerInterface $logger
	 * @param IRequest $request
	 * @param IGroupManager $groupManager
	 * @param IL10N $trans
	 * @param ISession $session
	 * @param PrivacyIDEAFactory $piFactory
	 */
	public function __construct(IAppConfig $appConfig, LoggerInterface $logger, IRequest $request, IGroupManager $groupManager, IL10N $trans, ISession $session, PrivacyIDEAFactory $piFactory)
	{
		$this->appConfig = $appConfig;
		$this->logger = $logger;
		$this->request = $request;
		$this->groupManager = $groupManager;
		$this->trans = $trans;
		$this->session = $session;
		$this->piFactory = $piFactory;
		if ($this->session->get('piAllowCreatingPIInstance') === true) {
			$this->pi = $this->piFactory->create();
		}
	}

	/**
	 * Get the template for rending the 2FA provider view.
	 *
	 * @param IUser $user
	 * @return Template
	 * @throws TwoFactorException
	 * @throws PIBadRequestException
	 */
	public function getTemplate(IUser $user): Template
	{
		if (!$this->isTwoFactorAuthEnabledForUser($user)) {
			$this->session->set('piNoAuthRequired', true);
			$this->verifyChallenge($user, '');
		} else {
			$this->session->set('piAllowCreatingPIInstance', true);
			$this->pi = $this->piFactory->create();

			$authenticationFlow = $this->getAppValue('piSelectedAuthFlow', 'piAuthFlowDefault');
			$this->log('debug', 'Selected authentication flow: ' . $authenticationFlow);
			$username = $user->getUID();
			$headers = [];
			$headersFromConfig = $this->getAppValue('piForwardHeaders', '');
			if (!empty($headersFromConfig)) {
				$headers = $this->getHeadersToForward($headersFromConfig);
			}

			if (!empty($this->pi) && $authenticationFlow === 'piAuthFlowTriggerChallenge') {
				if (!$this->pi->serviceAccountAvailable()) {
					$this->log('error', 'Service account name or password is not set in config. Cannot trigger the challenges.');
				} else {
					if ($this->session->get('piTriggerChallengeDone') !== true) {
						try {
							$response = $this->pi->triggerChallenge($username, $headers);
							$this->session->set('piTriggerChallengeDone', true);
							$this->processPIResponse($response);
						} catch (PIBadRequestException $e) {
							$this->handlePIException($e);
						}
					}
				}
			} elseif (!empty($this->pi) && $authenticationFlow === 'piAuthFlowSendStaticPass') {
				// Call /validate/check with a static pass from the configuration
				// This could already end up the authentication if the "passOnNoToken" policy is set.
				// Otherwise, it triggers the challenges.
				if ($this->session->get('piStaticPassDone') !== true) {
					$response = $this->pi->validateCheck($username, $this->getAppValue('piStaticPass', ''), '', $headers);
					$this->session->set('piStaticPassDone', true);
					if ($response !== null && $response->getAuthenticationStatus() === AuthenticationStatus::ACCEPT) {
						// Complete the authentication
						$this->session->set('piSuccess', true);
						$this->verifyChallenge($user, '');
					} else {
						$this->processPIResponse($response);
					}
				}
			} elseif ($authenticationFlow === 'piAuthFlowSeparateOTP') {
				$this->session->set('piSeparateOTP', true);
			} elseif ($authenticationFlow !== 'piAuthFlowDefault') {
				$this->log('error', 'Unknown authentication flow: ' . $authenticationFlow . '. Fallback to default.');
			}
		}

		// Set options, tokens and load counter to the template
		$template = new Template('privacyidea', 'main');

		$sessionToTemplate = [
			'piMessage' => ['message', $this->getAppValue('piDefaultMessage', 'Please enter the OTP!')],
			'piMode' => ['mode', null],
			'piWebAuthnSignRequest' => ['webAuthnSignRequest', null],
			'piPasskeyRegistration' => ['passkeyRegistration', null],
			'piPasskeyRegistrationSerial' => ['passkeyRegistrationSerial', null],
			'piPasskeyChallenge' => ['passkeyChallenge', null],
			'piPushOrSmartphoneContainerAvailable' => ['isPushAvailable', null],
			'piOTPAvailable' => ['otpAvailable', null],
			'piImgWebauthn' => ['imgWebauthn', null],
			'piImgPush' => ['imgPush', null],
			'piImgSmartphone' => ['imgSmartphone', null],
			'piImgOtp' => ['imgOtp', null],
			'piEnrollmentLink' => ['link', null],
			'piEnrollViaMultichallenge' => ['isEnrollViaMultichallenge', null],
			'piEnrollViaMultichallengeOptional' => ['isEnrollViaMultichallengeOptional', null],
			'piTransactionID' => ['transactionID', null],
			'piSeparateOTP' => ['separateOTP', null],
			'piPollInBrowserFailed' => ['pollInBrowserFailed', null],
			'piErrorMessage' => ['errorMessage', null],
			'piAutoSubmit' => ['autoSubmit', null],
		];

		foreach ($sessionToTemplate as $sessionKey => [$tplKey, $default]) {
			$val = $this->session->get($sessionKey);
			if ($val !== null) {
				$template->assign($tplKey, $val);
			} elseif ($sessionKey === 'piMessage' && empty($val)) {
				$template->assign($tplKey, $default);
			}
		}

		$configForTemplate = [
			'activateAutoSubmitOtpLength' => [$this->getAppValue('piActivateAutoSubmitOtpLength', '0')],
			'autoSubmitOtpLength' => [$this->getAppValue('piAutoSubmitOtpLength', '6')],
			'pollInBrowser' => [$this->getAppValue('piPollInBrowser', '0')],
			'pollInBrowserUrl' => [$this->getAppValue('piPollInBrowserURL', '')],
		];
		foreach ($configForTemplate as $tplKey => [$val]) {
			$template->assign($tplKey, $val);
		}

		// Load counter for PUSH polling
		$loads = 1;
		if ($this->session->get('piLoadCounter') !== null) {
			$loads = $this->session->get('piLoadCounter');
		}
		$template->assign('loadCounter', $loads);

		// Add translations
		$translationsForTemplate = [
			'verify' => [$this->trans->t('Verify')],
			'cancelEnrollment' => [$this->trans->t('Cancel enrollment')],
			'retryPasskeyRegistration' => [$this->trans->t('Retry passkey registration')],
			'alternateLoginOptions' => [$this->trans->t('Alternate login options')],
			'enrollmentLink' => [$this->trans->t('Enrollment link')],
		];
		foreach ($translationsForTemplate as $tplKey => [$val]) {
			$template->assign($tplKey, $val);
		}

		return $template;
	}

	/**
	 * Verify the given challenge.
	 *
	 * @param IUser $user
	 * @param string $challenge
	 * @return Bool True in case of success. In case of failure, this raises
	 *              a TwoFactorException with a descriptive error message.
	 * @throws TwoFactorException|Exception
	 */
	public function verifyChallenge(IUser $user, string $challenge): bool
	{
		if ($this->session->get('piNoAuthRequired') || $this->session->get('piSuccess')) {
			$this->session->set('piAutoSubmit', true);
			return true;
		}

		if (!empty($this->request->getParam('passField'))) {
			$password = $this->request->getParam('passField') . $challenge;
		} else {
			$password = $challenge;
		}
		$username = $user->getUID();
		$transactionID = $this->session->get('piTransactionID');
		$mode = $this->request->getParam('mode');
		$this->session->set('piMode', $mode);
		$headers = [];
		$headersFromConfig = $this->getAppValue('piForwardHeaders', '');
		if (!empty($headersFromConfig)) {
			$headers = $this->getHeadersToForward($headersFromConfig);
		}

		$piResponse = null;
		if ($this->request->getParam('modeChanged') === '1') {
			throw new TwoFactorException(' ');
		}

		// The client is only created when piAllowCreatingPIInstance is set and a
		// server URL is configured. If it is missing here (e.g. the session flag
		// was lost, or the URL is unset), fail with a clean error instead of a
		// fatal "typed property must not be accessed before initialization".
		if ($this->pi === null) {
			$this->log('error', 'Cannot verify challenge: no privacyIDEA client available (check the server URL configuration).');
			throw new TwoFactorException($this->trans->t('Failed to authenticate.'));
		}

		if (!empty($this->request->getParam('passkeySignResponse'))) {
			if (empty($this->request->getParam('origin'))) {
				$this->log('debug', 'Origin is missing for Passkey authentication!');
			} else {
				$passkeyTransactionID = $this->session->get('piPasskeyTransactionID');
				$passkeySignResponse = $this->request->getParam('passkeySignResponse');
				$origin = $this->request->getParam('origin');
				$piResponse = $this->pi->validateCheckPasskey($passkeyTransactionID, $passkeySignResponse, $origin, $headers);
				if (!empty($piResponse)) {
					if ($piResponse->isAuthenticationSuccessful()) {
						$this->session->set('piSuccess', true);
						return true;
					} elseif ($piResponse->getAuthenticationStatus() === AuthenticationStatus::CHALLENGE) {
						$this->processPIResponse($piResponse);
						throw new TwoFactorException(' ');
					} elseif ($piResponse->getAuthenticationStatus() === AuthenticationStatus::REJECT) {
						$this->log('error', 'Passkey authentication rejected!');
						$this->session->set('piErrorMessage', 'Passkey authentication rejected!');
						$this->session->set('piMode', 'otp');
						throw new TwoFactorException(' ');
					} elseif (!empty($piResponse->getErrorMessage())) {
						throw new TwoFactorException($piResponse->getErrorMessage());
					}
				}
			}
		}

		// Passkey login cancelled: Remove the challenge and passkey transaction ID
		if ($this->request->getParam('passkeyLoginCancelled') === '1') {
			$this->session->set('piMode', 'otp');
			throw new TwoFactorException(' ');
		}

		// Cancel enrollment via multichallenge if requested
		if (!empty($this->request->getParam('enrollmentCancelled'))) {
			$piResponse = $this->pi->validateCheckCancelEnrollment($transactionID, $headers);
			if (!empty($piResponse)) {
				if (!empty($piResponse->getErrorMessage())) {
					throw new TwoFactorException($piResponse->getErrorMessage());
				} elseif ($piResponse->isAuthenticationSuccessful()) {
					$this->session->set('piPasskeyRegistration', null);
					$this->session->set('piPasskeyRegistrationSerial', null);
					return true;
				}
			}
		}

		// Passkey registration: enroll_via_multichallenge. This happens after successful authentication
		if (!empty($this->request->getParam('passkeyRegistrationResponse'))) {
			$transactionID = $this->session->get('piTransactionID');
			$passkeyRegistrationSerial = $this->session->get('piPasskeyRegistrationSerial');
			$passkeyRegistrationResponse = $this->request->getParam('passkeyRegistrationResponse');
			$origin = $this->request->getParam('origin');
			$piResponse = $this->pi->validateCheckCompletePasskeyRegistration($transactionID, $passkeyRegistrationSerial, $username, $passkeyRegistrationResponse, $origin, $headers);
			if (!empty($piResponse)) {
				if (!empty($piResponse->getErrorMessage())) {
					throw new TwoFactorException($piResponse->getErrorMessage());
				} elseif ($piResponse->isAuthenticationSuccessful()) {
					$this->session->set('piPasskeyRegistration', null);
					$this->session->set('piPasskeyRegistrationSerial', null);
					return true;
				}
			}
		}

		if ($mode === 'push') {
			$this->log('debug', 'Processing PUSH response...');

			if ($this->pi->pollTransaction($transactionID)) {
				// The challenge has been answered. Now we need to verify it.
				$piResponse = $this->pi->validateCheck($username, '', $transactionID, $headers);
				$this->processPIResponse($piResponse);
			} else {
				$this->log('debug', 'PUSH not confirmed yet...');
			}

			// Increase load counter. loadCounter is a user-controllable form
			// field, so cast it before arithmetic (a non-numeric value would
			// otherwise raise a TypeError on PHP 8).
			if ($this->request->getParam('loadCounter')) {
				$counter = (int)$this->request->getParam('loadCounter');
				$this->session->set('piLoadCounter', $counter + 1);
			}
		} elseif ($mode === 'webauthn') {
			// The sign response is already a JSON string from the browser;
			// validateCheckWebAuthn parses it, so forward it as-is instead of
			// decoding and re-encoding here.
			$webAuthnSignResponse = (string)$this->request->getParam('webAuthnSignResponse');
			$origin = $this->request->getParam('origin');

			if (empty($webAuthnSignResponse)) {
				$this->log('error', 'Incomplete data for WebAuthn authentication: WebAuthn sign response is missing!');
			} else {
				$piResponse = $this->pi->validateCheckWebAuthn($username, $transactionID, $webAuthnSignResponse, $origin, $headers);
				$this->processPIResponse($piResponse);
			}
		} else {
			if (!empty($transactionID)) {
				$this->log('debug', 'Transaction ID: ' . $transactionID);
				$piResponse = $this->pi->validateCheck($username, $password, $transactionID, $headers);
			} else {
				$piResponse = $this->pi->validateCheck($username, $password, null, $headers);
			}
			$this->processPIResponse($piResponse);
		}

		if ($piResponse !== null) {
			if (!empty($piResponse->getErrorMessage())) {
				throw new TwoFactorException($piResponse->getErrorMessage());
			} else {
				if ($piResponse->getStatus() === true) {
					if ($piResponse->getAuthenticationStatus() === AuthenticationStatus::ACCEPT) {
						$this->log('debug', 'User authenticated successfully!');
						return true;
					} else {
						if (!empty($piResponse->getMessages())) {
							$this->session->set('piMessage', $piResponse->getMessages());
							$this->log('debug', $piResponse->getMessages());
						} else {
							$this->session->set('piMessage', $piResponse->getMessage());
							$this->log('debug', $piResponse->getMessage());
						}
					}
				} elseif ($mode === 'push') {
					$this->log('debug', 'PUSH not confirmed yet...');
				} else {
					// status === false
					$this->log('error', 'privacyIDEA error code: ' . $piResponse->getErrorCode());
					$this->log('error', 'privacyIDEA error message: ' . $piResponse->getErrorMessage());
					throw new TwoFactorException($this->trans->t('Failed to authenticate.') . ' ' . $piResponse->getErrorMessage());
				}
			}
		}
		throw new TwoFactorException(' ');
	}

	/**
	 *  Process the response from privacyIDEA and write information to session.
	 *
	 * @param PIResponse|null $response
	 * @return void
	 */
	private function processPIResponse(?PIResponse $response): void
	{
		if ($response === null) {
			$this->log('error', 'Cannot process response: the server response was empty or malformed.');
			$this->session->set('piErrorMessage', $this->trans->t('The privacyIDEA server returned an empty or malformed response.'));
			return;
		}
		$this->session->set('piMode', 'otp');
		if (!empty($response->getMultiChallenge())) {
			$triggeredTokens = $response->getTriggeredTokenTypes();
			if (!empty($response->getPreferredClientMode())) {
				if ($response->getPreferredClientMode() === 'interactive') {
					$this->session->set('piMode', 'otp');
				} elseif ($response->getPreferredClientMode() === 'poll') {
					$this->session->set('piMode', 'push');
				} else {
					$this->session->set('piMode', $response->getPreferredClientMode());
				}
				$this->log('debug', 'Preferred client mode: ' . $this->session->get('piMode'));
			}
			$this->session->set('piPushOrSmartphoneContainerAvailable', $response->isPushOrSmartphoneContainerAvailable());
			$this->session->set('piOTPAvailable', true);
			$this->session->set('piMessage', $response->getMessages());
			$this->session->set('piTransactionID', $response->getTransactionID());
			if (in_array('webauthn', $triggeredTokens)) {
				$this->session->set('piWebAuthnSignRequest', $response->getWebauthnSignRequest());
			}
			// Passkey registration
			if (!empty($response->getPasskeyRegistration()) && !empty($response->getSerial())) {
				$this->session->set('piPasskeyRegistration', $response->getPasskeyRegistration());
				$this->session->set('piMessage', $response->getMessage());
				$this->session->set('piPasskeyRegistrationSerial', $response->getPasskeyRegistrationSerial());
			}
			// Passkey challenge
			if (!empty($response->getPasskeyChallenge())) {
				$this->session->set('piPasskeyChallenge', $response->getPasskeyChallenge());
				$this->session->set('piPasskeyTransactionID', $response->getTransactionID());
			}

			// Search for the images & enrollment link
			foreach ($response->getMultiChallenge() as $challenge) {
				if (!empty($challenge->image)) {
					if (!empty($challenge->clientMode) && $challenge->clientMode === 'interactive') {
						$this->session->set('piImgOtp', $challenge->image);
						if ($response->isEnrollViaMultichallenge()) {
							$this->session->set('piMode', 'otp');
						}
					} elseif (!empty($challenge->clientMode) && $challenge->clientMode === 'poll') {
						if ($challenge->type === 'push') {
							$this->session->set('piImgPush', $challenge->image);
							if ($response->isEnrollViaMultichallenge()) {
								$this->session->set('piMode', 'push');
							}
						} elseif ($challenge->type === 'smartphone') {
							$this->session->set('piImgSmartphone', $challenge->image);
							if ($response->isEnrollViaMultichallenge()) {
								$this->session->set('piMode', 'push');
							}
						}
					} elseif (!empty($challenge->clientMode) && $challenge->clientMode === 'webauthn') {
						$this->session->set('piImgWebauthn', $challenge->image);
						if ($response->isEnrollViaMultichallenge()) {
							$this->session->set('piMode', 'webauthn');
						}
					}
				}
				if (!empty($challenge->enrollmentLink)) {
					$this->session->set('piEnrollmentLink', $challenge->enrollmentLink);
				}
				if (!empty($response->isEnrollViaMultichallenge())) {
					$this->session->set('piEnrollViaMultichallenge', true);
				}
				if (!empty($response->isEnrollViaMultichallengeOptional())) {
					$this->session->set('piEnrollViaMultichallengeOptional', true);
				}
			}
		} elseif (!empty($response->getErrorCode())) {
			// privacyIDEA returned an error, prepare it to display.
			$this->log('error', 'Error code: ' . $response->getErrorCode() . ', Error Message: ' . $response->getErrorMessage());
			$this->session->set('piErrorCode', $response->getErrorCode());
			$this->session->set('piErrorMessage', $response->getErrorMessage());
		} elseif ($response->getAuthenticationStatus() === AuthenticationStatus::ACCEPT) {
			// The user has been authenticated successfully.
			$this->log('info', $response->getMessage());
		} else {
			// Unexpected response
			$this->log('error', $response->getMessage());
			$this->session->set('piErrorMessage', $response->getMessage());
		}
	}

	/**
	 * Search for the configured headers in $_SERVER and return all found with their values.
	 *
	 * @return array Headers to forward with their values.
	 */
	private function getHeadersToForward(string $headers): array
	{
		$cleanHeaders = str_replace(' ', '', $headers);
		$arrHeaders = explode(',', $cleanHeaders);

		$headersToForward = [];
		foreach ($arrHeaders as $header) {
			if (array_key_exists($header, $_SERVER)) {
				$this->log('debug', 'Found matching header: ' . $header);
				$value = $_SERVER[$header];
				if (is_array($_SERVER[$header])) {
					$value = implode(',', $_SERVER[$header]);
				}
				$headersToForward[] = $header . ': ' . $value;
			} else {
				$this->log('debug', 'No values for header: ' . $header . ' found.');
			}
		}
		return $headersToForward;
	}

	/**
	 * Log the exceptions coming from the privacyIDEA.
	 * Also set the error code and message in the session.
	 *
	 * @param PIBadRequestException $e
	 * @return void
	 */
	private function handlePIException(PIBadRequestException $e): void
	{
		$this->log('error', 'Exception: ' . $e->getMessage());
		$this->session->set('piErrorCode', $e->getCode());
		$this->session->set('piErrorMessage', $e->getMessage());
	}

	/**
	 * Check whether 2FA is enabled for the given user.
	 *
	 * @param IUser $user
	 * @return bool
	 */
	public function isTwoFactorAuthEnabledForUser(IUser $user): bool
	{
		$piActive = $this->getAppValue('piActivatePI', '0');
		$piExcludeIPs = $this->getAppValue('piExcludeIPs', '');
		$piInExGroups = $this->getAppValue('piInExGroupsField', '');
		$piInOrExSelected = $this->getAppValue('piInOrExSelected', 'exclude');

		if ($piActive === '1') {
			if ($piExcludeIPs) {
				// ip2long() only understands IPv4 and returns false otherwise.
				// Bail out for non-IPv4 clients (e.g. IPv6) so that a false
				// client address can never compare equal to a false (i.e.
				// unparseable) exclude entry and silently skip MFA.
				$clientIP = ip2long($this->getClientIP());
				if ($clientIP !== false) {
					foreach (explode(',', $piExcludeIPs) as $address) {
						$address = trim($address);
						if ($address === '') {
							continue;
						}
						if (str_contains($address, '-')) {
							$range = explode('-', $address);
							$startIP = ip2long(trim($range[0]));
							$endIP = ip2long(trim($range[1] ?? ''));
							// Only match when both range bounds parse as IPv4.
							if ($startIP !== false && $endIP !== false && $clientIP >= $startIP && $clientIP <= $endIP) {
								return false;
							}
						} else {
							$excludeIP = ip2long($address);
							if ($excludeIP !== false && $clientIP === $excludeIP) {
								return false;
							}
						}
					}
				}
			}
			if (!empty($piInExGroups)) {
				$piInExGroups = str_replace(' ', '', $piInExGroups);
				$groups = explode(',', $piInExGroups);
				$checkEnabled = false;
				foreach ($groups as $group) {
					if ($this->groupManager->isInGroup($user->getUID(), trim($group))) {
						$this->log('debug', '[isTwoFactorEnabledForUser] The user ' . $user->getUID() . ' is in group ' . $group . '.');
						if ($piInOrExSelected === 'exclude') {
							$this->log('debug', '[isTwoFactorEnabledForUser] The group ' . $group . ' is excluded (User does not need MFA).');
							return false;
						}
						if ($piInOrExSelected === 'include') {
							$this->log('debug', '[isTwoFactorEnabledForUser] The group ' . $group . ' is included (User needs MFA).');
							return true;
						}
					}
					$this->log('debug', '[isTwoFactorEnabledForUser] The user ' . $user->getUID() . ' is not in group ' . $group . '.');
					if ($piInOrExSelected === 'exclude') {
						$this->log('debug', '[isTwoFactorEnabledForUser] The group ' . $group . ' is excluded (User may need MFA).');
						$checkEnabled = true;
					}
					if ($piInOrExSelected === 'include') {
						$this->log('debug', '[isTwoFactorEnabledForUser] The group ' . $group . ' is included (User may not need MFA).');
						$checkEnabled = false;
					}
				}
				if (!$checkEnabled) {
					return false;
				}
			}
			$this->log('debug', '[isTwoFactorAuthEnabledForUser] User needs MFA.');
			return true;
		}
		$this->log('debug', '[isTwoFactorAuthEnabledForUser] privacyIDEA is not enabled.');
		return false;
	}

	/**
	 * Retrieve a value from the privacyIDEA app configuration store.
	 *
	 * @param string $key application config key
	 * @param $default
	 * @return string
	 */
	private function getAppValue(string $key, $default): string
	{
		return $this->appConfig->getValueString('privacyidea', $key, $default);
	}

	/**
	 * Get the client IP address.
	 *
	 * @return string Client IP address or an empty string.
	 */
	public function getClientIP(): string
	{
		$clientIP = $this->request->getRemoteAddress();
		if (!empty($clientIP)) {
			return $clientIP;
		} else {
			$this->log('error', 'Cannot get client IP address.');
			return '';
		}
	}

	/**
	 * Get unique identifier of this 2FA provider.
	 *
	 * @return string
	 */
	public function getId(): string
	{
		return 'privacyidea';
	}

	/**
	 * Get the display name for selecting the 2FA provider.
	 *
	 * @return string
	 */
	public function getDisplayName(): string
	{
		return 'PrivacyIDEA';
	}

	/**
	 * Get the description for selecting the 2FA provider.
	 *
	 * @return string
	 */
	public function getDescription(): string
	{
		return 'Use PrivacyIDEA for multi-factor authentication';
	}

	/**
	 * Log a message with the given log level.
	 *
	 * @param $level
	 * @param $message
	 */
	private function log($level, $message): void
	{
		$context = ['app' => 'privacyIDEA'];
		if ($level === 'debug') {
			$this->logger->debug($message, $context);
		}
		if ($level === 'info') {
			$this->logger->info($message, $context);
		}
		if ($level === 'error') {
			$this->logger->error($message, $context);
		}
	}
}
