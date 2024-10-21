<?php

namespace OCA\PrivacyIDEA\Settings;

use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\Settings\ISettings;

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
