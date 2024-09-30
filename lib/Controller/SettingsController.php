<?php

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Controller;

use OCP\AppFramework\Controller;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;

class SettingsController extends Controller
{
    /** @var IL10N Translation */
    private $trans;
    /** @var IConfig Configuration object */
    private IConfig $config;

    /**
     * @param string $appName
     * @param IRequest $request
     * @param IL10N $trans
     * @param IConfig $config
     */
    public function __construct(string   $appName,
                                IRequest $request,
                                IL10N    $trans,
                                IConfig  $config)
    {
        parent::__construct($appName, $request);
        $this->trans = $trans;
        $this->config = $config;
    }

    /**
     * Set a configuration value in the privacyIDEA app config.
     *
     * @param string $key configuration key
     * @param string $value configuration value
     */
    public function setValue(string $key, string $value): void
    {
        $this->config->setAppValue("privacyidea", $key, $value);
    }

    /**
     * Retrieve a configuration from the privacyIDEA app config.
     *
     * @param string $key configuration key
     * @return string
     */
    public function getValue(string $key): string
    {
        return $this->config->getAppValue("privacyidea", $key);
    }
}