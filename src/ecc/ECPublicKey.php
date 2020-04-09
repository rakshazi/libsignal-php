<?php

declare(strict_types=1);

namespace Libsignal\ecc;

interface ECPublicKey
{
    public function serialize();

    public function getType();
}
