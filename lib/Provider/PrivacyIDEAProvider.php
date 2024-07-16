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
        $this->pi = $this->createPrivacyIDEAInstance();
    }

    /**
     * Get the template for rending the 2FA provider view
     *
     * @param IUser $user
     * @return Template
     * @throws TwoFactorException
     * @throws PIBadRequestException
     */
    public function getTemplate(IUser $user): Template
    {
        $authenticationFlow = $this->getAppValue("piSelectedAuthFlow", "piAuthFlowDefault");
        $username = $user->getUID();
        $headers = array();
        $headersFromConfig = $this->getAppValue("piForwardHeaders", "");
        if (!empty($headersFromConfig))
        {
            $headers = $this->getHeadersToForward($headersFromConfig);
        }

        // TriggerChallenge
        if ($authenticationFlow === "piAuthFlowTriggerChallenge")
        {
            if (!$this->pi->serviceAccountAvailable())
            {
                $this->log("error", "privacyIDEA: Service account name or password is not set in config. Cannot trigger the challenges.");
            }
            else
            {
                $response = null;
                try
                {
                    $response = $this->pi->triggerChallenge($username, $headers);
                }
                catch (PIBadRequestException $e)
                {
                    $this->handlePIException($e);
                }

                if ($response != null)
                {
                    if (!empty($response->getMultiChallenge()))
                    {
                        $this->processPIResponse($response);
                    }
                }
            }
        }
        elseif ($authenticationFlow === "piAuthFlowSendStaticPass")
        {
            // Call /validate/check with a static pass from the configuration
            // This could already end up the authentication if the "passOnNoToken" policy is set.
            // Otherwise, it triggers the challenges.
            $response = $this->pi->validateCheck($username, $this->getAppValue("piStaticPass", ""), "", $headers);
            if ($response->getAuthenticationStatus() === AuthenticationStatus::ACCEPT)
            {
                $this->session->set("piSuccess", true);
                $this->verifyChallenge($user, "");
            }
            elseif ($response->getAuthenticationStatus() === AuthenticationStatus::CHALLENGE)
            {
                $this->processPIResponse($response);
            }
        }
        elseif ($authenticationFlow === "piAuthFlowSeparateOTP")
        {
            $this->session->set("piSeparateOTP", true);
        }
        else
        {
            $this->log("error", "privacyIDEA: Unknown authentication flow: " . $authenticationFlow . ". Fallback to default.");
        }

        // Set options, tokens and load counter to the template
        $template = new Template("privacyidea", "main");

        $message = $this->session->get("piMessage");
        if ($message === null)
        {
            $message = $this->getAppValue("piDefaultMessage", "Please enter the OTP!");
        }
        $template->assign("message", $message);

        if ($this->session->get("piMode") !== null)
        {
            $template->assign("mode", $this->session->get("piMode"));
        }
        if ($this->session->get("piWebAuthnSignRequest") !== null)
        {
            $template->assign("webAuthnSignRequest", json_encode($this->session->get("piWebAuthnSignRequest")));
        }
        if ($this->session->get("piPushAvailable"))
        {
            $template->assign("pushAvailable", $this->session->get("piPushAvailable"));
        }
        if ($this->session->get("piOTPAvailable"))
        {
            $template->assign("otpAvailable", $this->session->get("piOTPAvailable"));
        }
        if ($this->session->get("piImgWebauthn") !== null)
        {
            $template->assign("imgWebauthn", $this->session->get("piImgWebauthn"));
        }
        if ($this->session->get("piImgPush") !== null)
        {
            $template->assign("imgPush", $this->session->get("piImgPush"));
        }
        if ($this->session->get("piImgOTP") !== null)
        {
            $template->assign("imgOTP", $this->session->get("piImgOTP"));
        }
        $template->assign("autoSubmitOtpLength", $this->getAppValue("piActivateAutoSubmitOtpLength", false));
        $template->assign("pollInBrowser", $this->getAppValue("piPollInBrowser", false));
        $template->assign("pollInBrowserUrl", $this->getAppValue("piPollInBrowserURL", ""));
        if ($this->session->get("piTransactionID") !== null)
        {
            $template->assign("transactionID", $this->session->get("piTransactionID"));
        }
        if ($this->session->get("piPollInBrowserFailed") !== null && $this->session->get("piPollInBrowserFailed") === true)
        {
            $template->assign("pollInBrowserFailed", $this->session->get("piPollInBrowserFailed"));
        }
        if ($this->session->get("piErrorMessage") !== null)
        {
            $template->assign("errorMessage", $this->session->get("piErrorMessage"));
        }

        $loads = 1;
        if ($this->session->get("piLoadCounter") !== null)
        {
            $loads = $this->session->get("piLoadCounter");
        }
        $template->assign("loadCounter", $loads);

        // Add translations
        $template->assign("verify", $this->trans->t("Verify"));
        $template->assign("alternateLoginOptions", $this->trans->t("Alternate Login Options"));

        return $template;
    }

    /**
     * Verify the given challenge.
     *
     * @param IUser $user
     * @param string $challenge
     * @return Bool True in case of success. In case of failure, this raises
     *         a TwoFactorException with a descriptive error message.
     * @throws TwoFactorException|Exception
     */
    public function verifyChallenge(IUser $user, string $challenge): bool
    {
        if ($this->session->get("piNoAuthRequired") || $this->session->get("piSuccess"))
        {
            return true;
        }

        $password = $challenge;
        $username = $user->getUID();

        // Get mode and transactionID
        $mode = $this->request->getParam("mode");
        $this->session->set("piMode", $mode);
        $transactionID = $this->session->get("piTransactionID");

        if ($this->request->getParam("modeChanged") === "1")
        {
            throw new TwoFactorException($this->session->get("piMessage"));
        }

        $piResponse = 0;

        if ($mode === "push")
        {
            $this->log("debug", "privacyIDEA: Processing PUSH response...");

            if ($this->pi->pollTransaction($transactionID))
            {
                // The challenge has been answered. Now we need to verify it.
                $piResponse = $this->pi->validateCheck($username, "", $transactionID);
            }
            else
            {
                $this->log("debug", "privacyIDEA: PUSH not confirmed yet...");
            }

            // Increase load counter
            if ($this->request->getParam("loadCounter"))
            {
                $counter = $this->request->getParam("loadCounter");
                $this->session->set("piLoadCounter", $counter + 1);
            }
        }
        elseif ($mode === "webauthn")
        {
            $webAuthnSignResponse = json_decode($this->request->getParam("webAuthnSignResponse"), true);
            $origin = $this->request->getParam("origin");

            if (empty($webAuthnSignResponse))
            {
                $this->log("error", "Incomplete data for WebAuthn authentication: WebAuthn sign response is missing!");
            }
            else
            {
                $piResponse = $this->pi->validateCheckWebAuthn($username, $transactionID, $webAuthnSignResponse, $origin);
            }
        }
        else
        {
            if (!empty($transactionID))
            {
                $this->log("debug", "Transaction ID: " . $transactionID);
                $piResponse = $this->pi->validateCheck($username, $password, $transactionID);
            }
            else
            {
                $piResponse = $this->pi->validateCheck($username, $password);
            }
        }

        // Show error from processPIResponse
        if (!empty($piResponse->getErrorMessage()))
        {
            $errorMessage = $piResponse->getErrorMessage();
        }
        else
        {
            if ($piResponse->getStatus() === true)
            {
                if ($piResponse->getAuthenticationStatus() === AuthenticationStatus::ACCEPT)
                {
                    $this->log("debug", "privacyIDEA: User authenticated successfully!");
                    return true;
                }
                else
                {
                    if (!empty($piResponse->getMessages()))
                    {
                        $errorMessage = $piResponse->getMessages();
                    }
                    else
                    {
                        $errorMessage = $piResponse->getMessage();
                        $this->log("debug", "privacyIDEA:" . $piResponse->getMessage());
                    }
                    $this->session->set("piMessage", $errorMessage);
                }
            }
            elseif ($mode === "push")
            {
                $errorMessage = $this->session->get("piMessage");
            }
            else
            {
                // status == false
                $this->log("error", "[authenticate] privacyIDEA error code: " . $piResponse->getErrorCode());
                $this->log("error", "[authenticate] privacyIDEA error message: " . $piResponse->getErrorMessage());
                $errorMessage = $this->trans->t("Failed to authenticate.") . " " . $piResponse->getErrorMessage();
            }
        }
        throw new TwoFactorException($errorMessage);
    }

    /**
     * Create a new privacyIDEA object with the given configuration.
     *
     * @return PrivacyIDEA|null privacyIDEA object or null on error.
     */
    private function createPrivacyIDEAInstance(): ?PrivacyIDEA
    {
        if (!empty($this->getAppValue("piURL", "")))
        {
            $pi = new PrivacyIDEA("nextCloud", $this->getAppValue("piURL", ""));
            $pi->setLogger($this->logger);
            $pi->setSSLVerifyHost($this->getAppValue("piSSLVerify", "true"));
            $pi->setServiceAccountName($this->getAppValue("piServiceName", ""));
            $pi->setServiceAccountPass($this->getAppValue("piServicePass", ""));
            $pi->setServiceAccountRealm($this->getAppValue("piServiceRealm", ""));
            $pi->setRealm($this->getAppValue("piRealm", ""));
            return $pi;
        }
        else
        {
            $this->log("error", "privacyIDEA: Cannot create privacyIDEA instance: Server URL missing in configuration!");
        }
        return null;
    }

    /**
     *  Process the response from privacyIDEA and write information to session.
     *
     * @param PIResponse $response
     * @return bool|null
     */
    private function processPIResponse(PIResponse $response): ?bool
    {
        $this->session->set("piMode", "otp");
        if (!empty($response->getMultiChallenge()))
        {
            // Authentication not complete, new challenges were triggered.
            $triggeredTokens = $response->triggeredTokenTypes();
            if (!empty($response->getPreferredClientMode()))
            {
                if ($response->getPreferredClientMode() === "interactive")
                {
                    $this->session->set("piMode", "otp");
                }
                elseif ($response->getPreferredClientMode() === "poll")
                {
                    $this->session->set("piMode", "push");
                }
                else
                {
                    $this->session->set("piMode", $response->getPreferredClientMode());
                }
                $this->log("debug", "privacyIDEA: Preferred client mode: " . $this->session->get("piMode"));
            }
            $this->session->set("piPushAvailable", in_array("push", $triggeredTokens));
            $this->session->set("piOTPAvailable", true);
            $this->session->set("piMessage", $response->getMessages());
            $this->session->set("piTransactionID", $response->getTransactionID());
            if (in_array("webauthn", $triggeredTokens))
            {
                $this->session->set("piWebAuthnSignRequest", $response->webAuthnSignRequest());
            }

            // Search for the images
            foreach ($response->getMultiChallenge() as $challenge)
            {
                if (!empty($challenge->image))
                {
                    if (!empty($challenge->clientMode) && $challenge->clientMode === "interactive")
                    {
                        $this->session->set("piImageOtp", $challenge->image);
                    }
                    elseif (!empty($challenge->clientMode) && $challenge->clientMode === "poll")
                    {
                        $this->session->set("piImagePush", $challenge->image);
                    }
                    elseif (!empty($challenge->clientMode) && $challenge->clientMode === "webauthn")
                    {
                        $this->session->set("piImageWebAuthn", $challenge->image);
                    }
                }
            }
        }
        elseif ($response->getValue())
        {
            // Authentication complete
            return true;
        }
        elseif (!empty($response->getErrorCode()))
        {
            // privacyIDEA returned an error, prepare it to display.
            $this->log("error", "privacyIDEA: Error code: " . $response->getErrorCode() . ", Error Message: " . $response->getErrorMessage());
            $this->session->set("piErrorCode", $response->getErrorCode());
            $this->session->set("piErrorMessage", $response->getErrorMessage());
        }
        else
        {
            // Unexpected response
            $this->log("error", "privacyIDEA: " . $response->getMessage());
            $this->session->set("piErrorMessage", $response->getMessage());
        }
        return null;
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

        $headersToForward = array();
        foreach ($arrHeaders as $header)
        {
            if (array_key_exists($header, $_SERVER))
            {
                $this->log("debug", "Found matching header: " . $header);
                $value = $_SERVER[$header];
                if (is_array($_SERVER[$header]))
                {
                    $value = implode(',', $_SERVER[$header]);
                }
                $header = array($header => $value);
                $headersToForward = array_push($headersToForward, $header);
            }
            else
            {
                $this->log("debug", "No values for header: " . $header . " found.");
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
        $this->log("error", "Exception: " . $e->getMessage());
        $this->session->set("piErrorCode", $e->getCode());
        $this->session->set("piErrorMessage", $e->getMessage());
    }

    /**
     * Check whether 2FA is enabled for the given user.
     *
     * @param IUser $user
     * @return bool
     */
    public function isTwoFactorAuthEnabledForUser(IUser $user): bool
    {
        $piActive = $this->getAppValue('piActivatePI', '');
        $piExcludeIPs = $this->getAppValue('piExcludeIPs', '');
        $piInExGroups = $this->getAppValue('piInExGroupsField', '');
        $piInOrExSelected = $this->getAppValue('piInOrExSelected', 'exclude');

        if ($piActive === "1")
        {
            if ($piExcludeIPs)
            {
                $ipAddresses = explode(",", $piExcludeIPs);
                $clientIP = ip2long($this->getClientIP());
                foreach ($ipAddresses as $address)
                {
                    if (str_contains($address, '-'))
                    {
                        $range = explode('-', $address);
                        $startIP = ip2long($range[0]);
                        $endIP = ip2long($range[1]);
                        if ($clientIP >= $startIP && $clientIP <= $endIP)
                        {
                            return false;
                        }
                    }
                    else
                    {
                        if ($clientIP === ip2long($address))
                        {
                            return false;
                        }
                    }
                }
            }
            if ($piInExGroups)
            {
                $piInExGroups = str_replace("|", ",", $piInExGroups);
                $groups = explode(",", $piInExGroups);
                $checkEnabled = false;
                foreach ($groups as $group)
                {
                    if ($this->groupManager->isInGroup($user->getUID(), trim($group)))
                    {
                        $this->log("debug", "[isTwoFactorEnabledForUser] The user " . $user->getUID() . " is in group " . $group . ".");
                        if ($piInOrExSelected === "exclude")
                        {
                            $this->log("debug", "[isTwoFactorEnabledForUser] The group " . $group . " is excluded (User does not need 2FA).");
                            return false;
                        }
                        if ($piInOrExSelected === "include")
                        {
                            $this->log("debug", "[isTwoFactorEnabledForUser] The group " . $group . " is included (User needs 2FA).");
                            return true;
                        }
                    }
                    $this->log("debug", "[isTwoFactorEnabledForUser] The user " . $user->getUID() . " is not in group " . $group . ".");
                    if ($piInOrExSelected === "exclude")
                    {
                        $this->log("debug", "[isTwoFactorEnabledForUser] The group " . $group . " is excluded (User may need 2FA).");
                        $checkEnabled = true;
                    }
                    if ($piInOrExSelected === "include")
                    {
                        $this->log("debug", "[isTwoFactorEnabledForUser] The group " . $group . " is included (User may not need 2FA).");
                        $checkEnabled = false;
                    }
                }
                if (!$checkEnabled)
                {
                    return false;
                }
            }
            $this->log("debug", "[isTwoFactorAuthEnabledForUser] User needs 2FA");
            return true;
        }
        $this->log("debug", "[isTwoFactorAuthEnabledForUser] privacyIDEA is not enabled.");
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
     * Retrieve the privacyIDEA instance base URL from the app configuration.
     * In case the stored URL ends with '/validate/check', this suffix is removed.
     * The returned URL always ends with a slash.
     *
     * @return string
     */
    private function getBaseUrl(): string
    {
        $url = $this->getAppValue('url', '');

        // Remove the "/validate/check" suffix of $url if it exists
        $suffix = "/validate/check";
        if (substr($url, -strlen($suffix)) === $suffix)
        {
            $url = substr($url, 0, -strlen($suffix));
        }

        // Ensure that $url ends with a slash
        if (substr($url, -1) !== "/")
        {
            $url .= "/";
        }
        return $url;
    }

    /**
     * Return an associative array that contains the options that should be passed to
     * the HTTP client service when creating HTTP requests.
     * @return array
     */
    private function getClientOptions(): array
    {
        $checkSSL = $this->getAppValue('piSSLVerify', '');
        $noProxy = $this->getAppValue('piNoProxy', '');
        $timeout = $this->getAppValue('piTimeout', '5');
        $options = ['headers' => ['user-agent' => "nextCloud Plugin"], // NOTE: Here, we check for `!== '0'` instead of `=== '1'` in order to verify certificates
            // by default just after app installation.
                    'verify'  => $checkSSL !== '0', 'debug' => false, 'exceptions' => false, 'timeout' => $timeout];
        if ($noProxy === "1")
        {
            $options["proxy"] = ["https" => "", "http" => ""];
        }
        return $options;
    }

    /**
     * Get the client IP address.
     *
     * @return mixed|string
     */
    public function getClientIP(): mixed
    {
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER))
        {
            return $_SERVER["HTTP_X_FORWARDED_FOR"];
        }
        else if (array_key_exists('REMOTE_ADDR', $_SERVER))
        {
            return $_SERVER["REMOTE_ADDR"];
        }
        else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER))
        {
            return $_SERVER["HTTP_CLIENT_IP"];
        }
        return '';
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
        $context = ["app" => "privacyIDEA"];
        if ($level === 'debug')
        {
            $this->logger->debug($message, $context);
        }
        if ($level === 'info')
        {
            $this->logger->info($message, $context);
        }
        if ($level === 'error')
        {
            $this->logger->error($message, $context);
        }
    }
}