<?php

declare(strict_types=1);

namespace Libsignal\groups\state;

abstract class SenderKeyStore
{
    abstract public function storeSenderKey($senderKeyId, $record);

    // [String senderKeyId, SenderKeyRecord record]

    abstract public function loadSenderKey($senderKeyId);

    // [String senderKeyId]
}
