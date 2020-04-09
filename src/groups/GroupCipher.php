<?php

declare(strict_types=1);

namespace Libsignal\groups;

use Libsignal\AESCipher;
use Libsignal\exceptions\DuplicateMessageException;
use Libsignal\exceptions\InvalidKeyException;
use Libsignal\exceptions\InvalidMessageException;
use Libsignal\exceptions\NoSessionException;
use Libsignal\protocol\SenderKeyMessage;

class GroupCipher
{
    protected $senderKeyStore;
    protected $senderKeyId;

    public function __construct($senderKeyStore, $senderKeyId)
    {
        $this->senderKeyStore = $senderKeyStore;
        $this->senderKeyId = $senderKeyId;
    }

    public function encrypt($paddedPlaintext)
    {
        try {
            $record = $this->senderKeyStore->loadSenderKey($this->senderKeyId);
            $senderKeyState = $record->getSenderKeyState();
            $senderKey = $senderKeyState->getSenderChainKey()->getSenderMessageKey();
            $ciphertext = $this->getCipherText($senderKey->getIv(), $senderKey->getCipherKey(), $paddedPlaintext);

            $senderKeyMessage = new SenderKeyMessage($senderKeyState->getKeyId(),
                                                                 $senderKey->getIteration(),
                                                                 $ciphertext,
                                                                 $senderKeyState->getSigningKeyPrivate());

            $senderKeyState->setSenderChainKey($senderKeyState->getSenderChainKey()->getNext());
            $this->senderKeyStore->storeSenderKey($this->senderKeyId, $record);

            return $senderKeyMessage->serialize();
        } catch (InvalidKeyIdException $e) {
            throw new NoSessionException($e->getMessage());
        }
    }

    public function decrypt($senderKeyMessageBytes)
    {
        try {
            $record = $this->senderKeyStore->loadSenderKey($this->senderKeyId);
            $senderKeyMessage = new SenderKeyMessage(null, null, null, null, $senderKeyMessageBytes);

            $senderKeyState = $record->getSenderKeyState($senderKeyMessage->getKeyId());
            $senderKeyMessage->verifySignature($senderKeyState->getSigningKeyPublic());
            $senderKey = $this->getSenderKey($senderKeyState, $senderKeyMessage->getIteration());

            $plaintext = $this->getPlainText($senderKey->getIv(), $senderKey->getCipherKey(), $senderKeyMessage->getCipherText());

            $this->senderKeyStore->storeSenderKey($this->senderKeyId, $record);

            return $plaintext;
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException($e->getMessage());
        }
    }

    public function getSenderKey($senderKeyState, $iteration)
    {
        $senderChainKey = $senderKeyState->getSenderChainKey();

        if ($senderChainKey->getIteration() > $iteration) {
            if ($senderKeyState->hasSenderMessageKey($iteration)) {
                return $senderKeyState->removeSenderMessageKey($iteration);
            }
            throw new DuplicateMessageException('Received message with old counter: '.$senderChainKey->getIteration().' '.$iteration);
        }

        if ($senderChainKey->getIteration() - $iteration > 2000) {
            throw new InvalidMessageException('Over 2000 messages into the future!');
        }

        while ($senderChainKey->getIteration() < $iteration) {
            $senderKeyState->addSenderMessageKey($senderChainKey->getSenderMessageKey());
            $senderChainKey = $senderChainKey->getNext();
        }

        $senderKeyState->setSenderChainKey($senderChainKey->getNext());

        return $senderChainKey->getSenderMessageKey();
    }

    public function getPlainText($iv, $key, $ciphertext)
    {
        try {
            $cipher = new AESCipher($key, $iv);
            $plaintext = $cipher->decrypt($ciphertext);

            return $plaintext;
        } catch (Exception $e) {
            throw new InvalidMessageException($e->getMessage());
        }
    }

    public function getCipherText($iv, $key, $plaintext)
    {
        $cipher = new AESCipher($key, $iv);

        return $cipher->encrypt($plaintext);
    }
}
