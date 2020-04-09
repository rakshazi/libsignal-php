<?php

declare(strict_types=1);

namespace Libsignal\kdf;

class HKDFv2 extends HKDF
{
    protected function getIterationStartOffset()
    {
        return 0;
    }
}
