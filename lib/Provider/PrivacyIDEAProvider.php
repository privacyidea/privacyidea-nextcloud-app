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
    /** @var PrivacyIDEA */
    private PrivacyIDEA $pi;

    /**
     * PrivacyIDEAProvider constructor.
     *
     * @param IAppConfig $appConfig
     * @param LoggerInterface $logger
     * @param IRequest $request
     * @param IGroupManager $groupManager
     * @param IL10N $trans
     * @param ISession $session
     */
    public function __construct(IAppConfig $appConfig, LoggerInterface $logger, IRequest $request, IGroupManager $groupManager, IL10N $trans, ISession $session)
    {
        $this->appConfig = $appConfig;
        $this->logger = $logger;
        $this->request = $request;
        $this->groupManager = $groupManager;
        $this->trans = $trans;
        $this->session = $session;
        if ($this->session->get('piAllowCreatingPIInstance') === true) {
            $this->pi = $this->createPrivacyIDEAInstance();
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
            $this->pi = $this->createPrivacyIDEAInstance();

            $authenticationFlow = $this->getAppValue('piSelectedAuthFlow', 'piAuthFlowDefault');
            $this->log('debug', 'Selected authentication flow: ' . $authenticationFlow);
            $username = $user->getUID();
            $headers = [];
            $headersFromConfig = $this->getAppValue('piForwardHeaders', '');
            if (!empty($headersFromConfig)) {
                $headers = $this->getHeadersToForward($headersFromConfig);
            }

            if ($authenticationFlow === 'piAuthFlowTriggerChallenge') {
                if (!empty($this->pi)) {
                    if (!$this->pi->serviceAccountAvailable()) {
                        $this->log('error', 'Service account name or password is not set in config. Cannot trigger the challenges.');
                    } else {
                        if ($this->session->get('piTriggerChallengeDone') !== true) {
                            try {
                                $response = $this->pi->triggerChallenge($username, $headers);
                                $this->session->set('piTriggerChallengeDone', true);
                                if ($response !== null) {
                                    $this->processPIResponse($response);
                                } else {
                                    $this->log('error', 'No response from privacyIDEA server for triggerchallenge.');
                                }
                            }
                            catch (PIBadRequestException $e) {
                                $this->handlePIException($e);
                            }
                        }
                    }
                }
            } elseif ($authenticationFlow === 'piAuthFlowSendStaticPass') {
                // Call /validate/check with a static pass from the configuration
                // This could already end up the authentication if the "passOnNoToken" policy is set.
                // Otherwise, it triggers the challenges.
                if ($this->session->get('piStaticPassDone') !== true) {
                    $response = $this->pi->validateCheck($username, $this->getAppValue('piStaticPass', ''), '', $headers);
                    $this->session->set('piStaticPassDone', true);
                    if ($response->getAuthenticationStatus() === AuthenticationStatus::ACCEPT) {
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

        if (!empty($this->session->get('piMessage'))) {
            $template->assign('message', $this->session->get('piMessage'));
        } else {
            $template->assign('message', $this->getAppValue('piDefaultMessage', 'Please enter the OTP!'));
        }
        if ($this->session->get('piMode') !== null) {
            $template->assign('mode', $this->session->get('piMode'));
        }
        if ($this->session->get('piWebAuthnSignRequest') !== null) {
            $template->assign('webAuthnSignRequest', $this->session->get('piWebAuthnSignRequest'));
        }
        if ($this->session->get('piPasskeyRegistration') !== null) {
            $template->assign('passkeyRegistration', $this->session->get('piPasskeyRegistration'));
        }
        if ($this->session->get('piPasskeyRegistrationSerial') !== null) {
            $template->assign('passkeyRegistrationSerial', $this->session->get('piPasskeyRegistrationSerial'));
        }
        if ($this->session->get('piPasskeyChallenge') !== null) {
            $template->assign('passkeyChallenge', $this->session->get('piPasskeyChallenge'));
        }
        if ($this->session->get('piPushAvailable')) {
            $template->assign('pushAvailable', $this->session->get('piPushAvailable'));
        }
        if ($this->session->get('piOTPAvailable')) {
            $template->assign('otpAvailable', $this->session->get('piOTPAvailable'));
        }
        if ($this->session->get('piImgWebauthn') !== null) {
            $template->assign('imgWebauthn', $this->session->get('piImgWebauthn'));
        }
        if ($this->session->get('piImgPush') !== null) {
            $template->assign('imgPush', $this->session->get('piImgPush'));
        }
        if ($this->session->get('piImgOTP') !== null) {
            $template->assign('imgOTP', $this->session->get('piImgOTP'));
        }
        if ($this->session->get('piEnrollViaMultichallenge') !== null) {
            $template->assign('isEnrollViaMultichallenge', $this->session->get('isEnrollViaMultichallenge'));
        }
        if ($this->session->get('piEnrollmentLink') !== null) {
            $template->assign('enrollmentLink', $this->session->get('piEnrollmentLink'));
        }
        $template->assign('activateAutoSubmitOtpLength', $this->getAppValue('piActivateAutoSubmitOtpLength', '0'));
        $template->assign('autoSubmitOtpLength', $this->getAppValue('piAutoSubmitOtpLength', '6'));
        $template->assign('pollInBrowser', $this->getAppValue('piPollInBrowser', '0'));
        $template->assign('pollInBrowserUrl', $this->getAppValue('piPollInBrowserURL', ''));
        if ($this->session->get('piTransactionID') !== null) {
            $template->assign('transactionID', $this->session->get('piTransactionID'));
        }
        if ($this->session->get('piSeparateOTP') !== null && $this->session->get('piSeparateOTP') === true) {
            $template->assign('separateOTP', $this->session->get('piSeparateOTP'));
        }
        if ($this->session->get('piPollInBrowserFailed') !== null && $this->session->get('piPollInBrowserFailed') === true) {
            $template->assign('pollInBrowserFailed', $this->session->get('piPollInBrowserFailed'));
        }
        if ($this->session->get('piErrorMessage') !== null) {
            $template->assign('errorMessage', $this->session->get('piErrorMessage'));
        }
        if ($this->session->get('piAutoSubmit') !== null && $this->session->get('piAutoSubmit') === true) {
            $template->assign('autoSubmit', $this->session->get('piAutoSubmit'));
        }

        $loads = 1;
        if ($this->session->get('piLoadCounter') !== null) {
            $loads = $this->session->get('piLoadCounter');
        }
        $template->assign('loadCounter', $loads);

        // Add translations
        $template->assign('verify', $this->trans->t('Verify'));
        $template->assign('alternateLoginOptions', $this->trans->t('Alternate Login Options'));

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

        if (!empty($this->request->getParam('passkeySignResponse'))) {
            if (empty($this->request->getParam('origin'))) {
                $this->log("debug", "Origin is missing for Passkey authentication!");
            } else {
                $passkeyTransactionID = $this->session->get('piPasskeyTransactionID');
                $passkeySignResponse = $this->request->getParam('passkeySignResponse');
                $origin = $this->request->getParam('origin');
                $piResponse = $this->pi->validateCheckPasskey($passkeyTransactionID, $passkeySignResponse, $origin, $headers);
                if (!empty($piResponse)) {
                    if ($piResponse->isAuthenticationSuccessful()) {
                        $this->log('debug', 'Passkey authentication successful!');
                        $this->session->set('piSuccess', true);
                        return true;
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

        // Passkey login requested: Get a challenge and return
        if ($this->request->getParam('passkeyLoginRequested') === '1') {
            $piResponse = $this->pi->validateInitialize("passkey");
            if (!empty($piResponse)) {
                $this->session->set('piPasskeyMessage', $piResponse->getPasskeyMessage());
                $this->session->set('piPasskeyChallenge', $piResponse->getPasskeyChallenge());
                $this->session->set('piMode', 'passkey');
                $this->session->set('piPasskeyTransactionID', $piResponse->getTransactionID());
                throw new TwoFactorException(' ');
            }
        }

        // Passkey login cancelled: Remove the challenge and passkey transaction ID
        if ($this->request->getParam('passkeyLoginCancelled') === '1') {
            $this->session->set('piPasskeyChallenge', '');
            $this->session->set('piPasskeyTransactionID', null);
        }

        // Passkey registration: enroll_via_multichallenge. This happens after successful authentication
        if (!empty($this->request->getParam('passkeyRegistrationResponse'))) {
            $transactionID = $this->session->get('piTransactionID');
            $passkeyRegistrationSerial = $this->request->getParam('passkeyRegistrationSerial'); //todo check if request or session here
            $passkeyRegistrationResponse = $this->request->getParam('piPasskeyRegistrationResponse');
            $origin = $this->request->getParam('origin');
            $piResponse = $this->pi->validateCheckCompletePasskeyRegistration($transactionID, $passkeyRegistrationSerial, $username, $passkeyRegistrationResponse, $origin, $headers);
            if (!empty($piResponse)) {
                if (!empty($piResponse->getErrorMessage())) {
                    throw new TwoFactorException($piResponse->getErrorMessage());
                } elseif($piResponse->isAuthenticationSuccessful()) {
                    $this->session->set('piPasskeyRegistration', null);
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

            // Increase load counter
            if ($this->request->getParam('loadCounter')) {
                $counter = $this->request->getParam('loadCounter');
                $this->session->set('piLoadCounter', $counter + 1);
            }
        } elseif ($mode === 'webauthn') {
            $webAuthnSignResponse = json_decode($this->request->getParam('webAuthnSignResponse'), true);
            $origin = $this->request->getParam('origin');

            if (empty($webAuthnSignResponse)) {
                $this->log('error', 'Incomplete data for WebAuthn authentication: WebAuthn sign response is missing!');
            } else {
                $piResponse = $this->pi->validateCheckWebAuthn($username, $transactionID, json_encode($webAuthnSignResponse), $origin, $headers);
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
     * Create a new privacyIDEA object with the given configuration.
     *
     * @return PrivacyIDEA|null privacyIDEA object or null on error.
     */
    private function createPrivacyIDEAInstance(): ?PrivacyIDEA
    {
        $this->log('info', 'Creating privacyIDEA instance...');
        if (!empty($this->getAppValue('piURL', ''))) {
            $pi = new PrivacyIDEA('privacyidea-nextcloud/1.0.0', $this->getAppValue('piURL', ''));
            $pi->setLogger($this->logger);
            $pi->setSSLVerifyHost($this->getAppValue('piSSLVerify', true));
            $pi->setSSLVerifyPeer($this->getAppValue('piSSLVerify', true));
            $pi->setServiceAccountName($this->getAppValue('piServiceName', ''));
            $pi->setServiceAccountPass($this->getAppValue('piServicePass', ''));
            $pi->setServiceAccountRealm($this->getAppValue('piServiceRealm', ''));
            $pi->setRealm($this->getAppValue('piRealm', ''));
            $pi->setNoProxy($this->getAppValue('piNoProxy', false));
            if ($this->getAppValue('piForwardClientIP', false) && !empty($this->getClientIP())) {
                $pi->setForwardClientIP($this->getClientIP());
            }
            return $pi;
        } else {
            $this->log('error', 'Cannot create privacyIDEA instance: Server URL missing in configuration!');
        }
        return null;
    }

    /**
     *  Process the response from privacyIDEA and write information to session.
     *
     * @param PIResponse $response
     * @return void
     */
    private function processPIResponse(PIResponse $response): void
    {
        $this->log('info', 'Processing server response...');
        $this->session->set('piMode', 'otp');
        $this->log('info', 'Authentication status: ' . $response->getAuthenticationStatus());
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
            $this->session->set('piPushAvailable', in_array('push', $triggeredTokens));
            $this->session->set('piOTPAvailable', true);
            $this->session->set('piMessage', $response->getMessages());
            $this->session->set('piTransactionID', $response->getTransactionID());
            if (in_array('webauthn', $triggeredTokens)) {
                $this->session->set('piWebAuthnSignRequest', $response->getWebauthnSignRequest());
            }
            // Passkey registration
            if (!empty($response->getPasskeyRegistration()) && !empty($response->getSerial())) {
                $this->session->set('piPasskeyRegistration', $response->getPasskeyRegistration());
                $this->session->set('piPasskeyRegistrationSerial', $response->getSerial());
            }
            // Passkey challenge
            if (!empty($response->getPasskeyChallenge())) {
                $this->session->set('piPasskeyChallenge', $response->getPasskeyChallenge());
            }

            // Search for the images & enrollment link
            foreach ($response->getMultiChallenge() as $challenge) {
                if (!empty($challenge->image)) {
                    $this->session->set('piIsEnrollViaMultichallenge', $challenge->enrollViaMultichallenge);
                    if (!empty($challenge->clientMode) && $challenge->clientMode === 'interactive') {
                        $this->session->set('piImageOtp', $challenge->image);
                    } elseif (!empty($challenge->clientMode) && $challenge->clientMode === 'poll') {
                        $this->session->set('piImagePush', $challenge->image);
                    } elseif (!empty($challenge->clientMode) && $challenge->clientMode === 'webauthn') {
                        $this->session->set('piImageWebAuthn', $challenge->image);
                    }
                }
                if (!empty($challenge->enrollmentLink)) {
                    $this->session->set('piEnrollmentLink', $challenge->enrollmentLink);
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
                $header = [$header => $value];
                $headersToForward = array_push($headersToForward, $header);
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
                $ipAddresses = explode(',', $piExcludeIPs);
                $clientIP = ip2long($this->getClientIP());
                foreach ($ipAddresses as $address) {
                    if (str_contains($address, '-')) {
                        $range = explode('-', $address);
                        $startIP = ip2long($range[0]);
                        $endIP = ip2long($range[1]);
                        if ($clientIP >= $startIP && $clientIP <= $endIP) {
                            return false;
                        }
                    } else {
                        if ($clientIP === ip2long($address)) {
                            return false;
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
