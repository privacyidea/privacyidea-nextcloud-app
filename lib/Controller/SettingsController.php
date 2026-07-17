<?php

declare(strict_types=1);

namespace OCA\PrivacyIDEA\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\DataResponse;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;

class SettingsController extends Controller
{
	/** @var IL10N Translation */
	private $trans;
	/** @var IConfig Configuration object */
	private IConfig $config;
	private IAppConfig $appConfig;

	/**
	 * @param string $appName
	 * @param IRequest $request
	 * @param IL10N $trans
	 * @param IConfig $config
	 * @param IAppConfig $appConfig
	 */
	public function __construct(string $appName, IRequest $request, IL10N $trans, IConfig $config, IAppConfig $appConfig)
	{
		parent::__construct($appName, $request);
		$this->trans = $trans;
		$this->config = $config;
		$this->appConfig = $appConfig;
	}

	/**
	 * Set a configuration value in the privacyIDEA app config.
	 *
	 * @param string $key configuration key
	 * @param string $value configuration value
	 * @return DataResponse
	 */
	public function setValue(string $key, string $value): DataResponse
	{
		$this->appConfig->setValueString('privacyidea', $key, $value);
		return new DataResponse([]);
	}

	/**
	 * Retrieve a configuration from the privacyIDEA app config.
	 *
	 * @param string $key configuration key
	 * @return DataResponse
	 */
	public function getValue(string $key): DataResponse
	{
		return new DataResponse($this->appConfig->getValueString('privacyidea', $key));
	}
}
