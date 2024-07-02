<?php

namespace OCA\PrivacyIDEA\Provider;

use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Http\Client\IClientService;
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
    /** @var IClientService */
    private IClientService $clientService;
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

    /**
     * PrivacyIDEAProvider constructor.
     *
     * @param IClientService $clientService
     * @param IAppConfig $config
     * @param LoggerInterface $logger
     * @param IRequest $request
     * @param IGroupManager $groupManager
     * @param IL10N $trans
     * @param ISession $session
     */
    public function __construct(IClientService  $clientService,
                                IAppConfig      $appConfig,
                                LoggerInterface $logger,
                                IRequest        $request,
                                IGroupManager   $groupManager,
                                IL10N           $trans,
                                ISession        $session)
    {
        $this->clientService = $clientService;
        $this->appConfig = $appConfig;
        $this->logger = $logger;
        $this->request = $request;
        $this->groupManager = $groupManager;
        $this->trans = $trans;
        $this->session = $session;
    }

    /**
     * Get the template for rending the 2FA provider view
     *
     * @param IUser $user
     * @return Template
     * @since 9.1.0
     *
     */
    public function getTemplate(IUser $user): Template
    {
        // TODO: Implement getTemplate() method.
    }

    /**
     * Verify the given challenge
     *
     * @param IUser $user
     * @param string $challenge
     * @return bool
     * @since 9.1.0
     *
     */
    public function verifyChallenge(IUser $user, string $challenge): bool
    {
        // TODO: Implement verifyChallenge() method.
    }

    /**
     * Decides whether 2FA is enabled for the given user
     *
     * @param IUser $user
     * @return bool
     * @since 9.1.0
     *
     */
    public function isTwoFactorAuthEnabledForUser(IUser $user): bool
    {
        $piActive = $this->getAppValue('piActivatePI', '');
        $piExcludeIPs = $this->getAppValue('piExcludeIPs', '');
        $piInExGroups = $this->getAppValue('piInExGroupsField', '');
        $piInOrExSelected = $this->getAppValue('piInOrExSelected', 'exclude');

        if ($piActive === "1") {
            if ($piExcludeIPs) {
                $ipAddresses = explode(",", $piExcludeIPs);
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
            if ($piInExGroups) {
                $piInExGroups = str_replace("|", ",", $piInExGroups);
                $groups = explode(",", $piInExGroups);
                $checkEnabled = false;
                foreach ($groups as $group) {
                    if ($this->groupManager->isInGroup($user->getUID(), trim($group))) {
                        $this->log("debug", "[isTwoFactorEnabledForUser] The user " . $user->getUID() . " is in group " . $group . ".");
                        if ($piInOrExSelected === "exclude") {
                            $this->log("debug", "[isTwoFactorEnabledForUser] The group " . $group . " is excluded (User does not need 2FA).");
                            return false;
                        }
                        if ($piInOrExSelected === "include") {
                            $this->log("debug", "[isTwoFactorEnabledForUser] The group " . $group . " is included (User needs 2FA).");
                            return true;
                        }
                    }
                }
            }
        }
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
     * @return mixed|string
     */
    public function getClientIP(): mixed
    {
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
            return $_SERVER["HTTP_X_FORWARDED_FOR"];
        } else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            return $_SERVER["REMOTE_ADDR"];
        } else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
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