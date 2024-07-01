<?php

declare(strict_types=1);

namespace OCA\PrivacyIDEA\AppInfo;

use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCA\PrivacyIDEA\Settings\Admin;
use Psr\Container\ContainerInterface;

class Application extends App implements IBootstrap
{
    public const APP_ID = 'privacyidea';

    /** @psalm-suppress PossiblyUnusedMethod */
    public function __construct()
    {
        parent::__construct(self::APP_ID);
    }

    public function register(IRegistrationContext $context): void
    {
        /*$context->registerService('settings-admin', function (ContainerInterface $c) {
            return new Admin();
        });*/
    }

    public function boot(IBootContext $context): void
    {
    }
}
