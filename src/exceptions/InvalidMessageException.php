<?php

declare(strict_types=1);

namespace Libsignal\exceptions;

class InvalidMessageException extends \Exception
{
    public function __construct($detailMessage, $throw = null) // [String detailMessage]
    {
        $this->message = $detailMessage;
        if (null !== $throw) {
            $this->previous = $throw;
        }
    }
}
