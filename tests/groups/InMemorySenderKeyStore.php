<?php

declare(strict_types=1);

namespace Libsignal\Tests\groups;

use Libsignal\groups\state\SenderKeyRecord;
use Libsignal\groups\state\SenderKeyStore;

class InMemorySenderKeyStore extends SenderKeyStore
{
    protected $store;

    public function __construct()
    {
        $this->store = [];
    }

    public function storeSenderKey($senderKeyId, $senderKeyRecord): void
    {
        $this->store[$senderKeyId] = $senderKeyRecord;
    }

    public function loadSenderKey($senderKeyId)
    {
        if (isset($this->store[$senderKeyId])) {
            return new SenderKeyRecord($this->store[$senderKeyId]->serialize());
        }

        return new SenderKeyRecord();
    }
}
