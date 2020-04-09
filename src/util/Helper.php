<?php

declare(strict_types=1);

namespace Libsignal\util;

class Helper
{
    public static function checkNotNull($reference, $message = null)
    {
        if (null === $message) {
            $message = 'Unallowed null in reference found.';
        }

        if (null === $reference) {
            throw new \Exception($message);
        }

        return $reference;
    }
}
