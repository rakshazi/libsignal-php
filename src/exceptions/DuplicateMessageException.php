<?php

declare(strict_types=1);

namespace Libsignal\exceptions;

class DuplicateMessageException extends \Exception
{
    public function __construct($s) // [String s]
    {
        $this->message = $s;
    }
}
