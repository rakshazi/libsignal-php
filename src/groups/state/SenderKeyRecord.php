<?php

declare(strict_types=1);

namespace Libsignal\groups\state;

use Libsignal\exceptions\InvalidKeyIdException;
use Localstorage\SenderKeyRecordStructure as TextSecure_SenderKeyRecordStructure;

class SenderKeyRecord
{
    protected $senderKeyStates;

    public function __construct($serialized = null)
    {
        $this->senderKeyStates = [];

        if (null !== $serialized) {
            $senderKeyRecordStructure = new TextSecure_SenderKeyRecordStructure();

            $senderKeyRecordStructure->parseFromString($serialized);

            foreach ($senderKeyRecordStructure->getSenderKeyStates() as $structure) {
                $this->senderKeyStates[] = new SenderKeyState(null, null, null, null, null, null, $structure);
            }
        }
    }

    public function getSenderKeyState($keyId = null)
    {
        if (null === $keyId) {
            if (\count($this->senderKeyStates) > 0) {
                return $this->senderKeyStates[0];
            }
            throw new InvalidKeyIdException('No key state in record');
        }
        foreach ($this->senderKeyStates as $state) {
            if ($state->getKeyId() === $keyId) {
                return $state;
            }
        }
        throw new InvalidKeyIdException("No keys for: $keyId");
    }

    public function addSenderKeyState($id, $iteration, $chainKey, $signatureKey): void
    {
        $this->senderKeyStates[] = new SenderKeyState($id, $iteration, $chainKey, $signatureKey);
    }

    public function setSenderKeyState($id, $iteration, $chainKey, $signatureKey): void
    {
        unset($this->senderKeyStates);
        $this->senderKeyStates = [];
        $this->senderKeyStates[] = new SenderKeyState($id, $iteration, $chainKey, null, null, $signatureKey);
    }

    public function serialize()
    {
        $recordStructure = new TextSecure_SenderKeyRecordStructure();

        foreach ($this->senderKeyStates as $senderKeyState) {
            $recordStructure->appendSenderKeyStates($senderKeyState->getStructure());
        }

        return $recordStructure->serializeToString();
    }
}
