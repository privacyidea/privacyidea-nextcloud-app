<?php

namespace OCA\PrivacyIDEA\Settings;

use OCP\AppFramework\Http\TemplateResponse;
use OCP\Settings\ISettings;
use OCP\IConfig;

class Admin implements ISettings
{
    private IConfig $config;

    public function __construct(IConfig $config)
    {
        $this->config = $config;
    }

    /**
     * @return TemplateResponse
     */
    public function getForm(): TemplateResponse
    {
        return new TemplateResponse('privacyidea', 'settings-admin', [], '');
    }

    public function getSection(): string
    {
        return 'privacyidea';
    }

    public function getPriority(): int
    {
        return 10;
    }
}