<?php

declare(strict_types=1);

namespace Libsignal\logging;

class AxolotlLoggerProvider
{
    protected static $provider;    // AxolotlLogger

    public static function getProvider()
    {
        return self::$provider;
    }

    public static function setProvider($provider): void // [AxolotlLogger provider]
    {
        self::$provider = $provider;
    }
}
