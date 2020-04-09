<?php

declare(strict_types=1);

namespace Libsignal\Tests;

//from axolotl.state.signedprekeystore import SignedPreKeyStore
//from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
//from axolotl.invalidkeyidexception import InvalidKeyIdException
use Libsignal\exceptions\InvalidKeyIdException;
use Libsignal\state\SignedPreKeyRecord;
use Libsignal\state\SignedPreKeyStore;

class InMemorySignedPreKeyStore extends SignedPreKeyStore
{
    protected $store;

    public function __construct()
    {
        $this->store = [];
    }

    public function loadSignedPreKey($signedPreKeyId)
    {
        if (!isset($this->store[$signedPreKeyId])) {
            throw new  InvalidKeyIdException('No such signedprekeyrecord! '.$signedPreKeyId);
        }

        return new  SignedPreKeyRecord(null, null, null, null, $this->store[$signedPreKeyId]);
    }

    public function loadSignedPreKeys()
    {
        $results = [];
        foreach ($this->store as $serialized) {
            $results[] = new SignedPreKeyRecord(null, null, null, null, $serialized);
        }

        return $results;
    }

    public function storeSignedPreKey($signedPreKeyId, $signedPreKeyRecord): void
    {
        $this->store[$signedPreKeyId] = $signedPreKeyRecord->serialize();
    }

    public function containsSignedPreKey($signedPreKeyId)
    {
        return isset($this->store[$signedPreKeyId]);
    }

    public function removeSignedPreKey($signedPreKeyId): void
    {
        unset($this->store[$signedPreKeyId]);
    }
}
