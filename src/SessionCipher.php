<?php

declare(strict_types=1);

/**
 * Copyright (C) 2013 Open Whisper Systems.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace Libsignal;

use Illuminate\Support\Facades\Log;
use Libsignal\ecc\Curve;
use Libsignal\exceptions\DuplicateMessageException;
use Libsignal\exceptions\InvalidMessageException;
use Libsignal\exceptions\NoSessionException;
use Libsignal\protocol\CiphertextMessage;
use Libsignal\protocol\PreKeyWhisperMessage;
use Libsignal\protocol\WhisperMessage;
use Libsignal\ratchet\ChainKey;
use Libsignal\ratchet\MessageKeys;
use Libsignal\state\SessionRecord;
use Libsignal\state\SessionState;
//require_once "/state/SessionState/UnacknowledgedPreKeyMessageItems.php";
use Libsignal\util\ByteUtil;

class SessionCipher
{
    protected $sessionStore;
    protected $preKeyStore;
    protected $recepientId;
    protected $deviceId;
    protected $sessionBuilder;

    public function __construct($sessionStore, $preKeyStore, $signedPreKeyStore, $identityKeyStore, $recepientId, $deviceId)
    {
        $this->sessionStore = $sessionStore;
        $this->preKeyStore = $preKeyStore;
        $this->recipientId = $recepientId;
        $this->deviceId = $deviceId;
        $this->sessionBuilder = new SessionBuilder($sessionStore, $preKeyStore, $signedPreKeyStore, $identityKeyStore, $recepientId, $deviceId);
    }

    public function encrypt($paddedMessage)
    {
        // :type paddedMessage: str

        /*
         * paddedMessage = bytearray(paddedMessage.encode()
         *
         * if (sys.version_info >= (3,0) and not type(paddedMessage) in (bytes, bytearray)) or type(paddedMessage) is unicode else paddedMessage)
         *
         */
        $sessionRecord = $this->sessionStore->loadSession($this->recipientId, $this->deviceId);
        $sessionState = $sessionRecord->getSessionState();
        $chainKey = $sessionState->getSenderChainKey();
        $messageKeys = $chainKey->getMessageKeys();
        $senderEphemeral = $sessionState->getSenderRatchetKey();
        $previousCounter = $sessionState->getPreviousCounter();
        $sessionVersion = $sessionState->getSessionVersion();
        $ciphertextBody = $this->getCiphertext($sessionVersion, $messageKeys, $paddedMessage);

//        Log::info(json_encode(["encrypt:" , "senderEphemeral" => bin2hex($senderEphemeral->getPublicKey()), "chainKey->getKey"=>bin2hex($chainKey->getKey()),"messageKeys->getCipherKey"=>bin2hex($messageKeys->getCipherKey()),"msgMACKey"=>bin2hex($messageKeys->getMacKey())]));
        // $messageVersion = null, $registrationId = null,$preKeyId = null,$signedPreKeyId = null,$ecPublicBaseKey = null,$identityKey = null,$whisperMessage = null,$serialized = null
        //$ciphertextMessage = new PreKeyWhisperMessage($sessionVersion, $recepientId,1,$sessionState->);
        //$ciphertextMessage  = new WhisperMessage($sessionVersion, $messageKeys->getMacKey(), $senderEphemeral, $chainKey->getIndex(), $previousCounter, $ciphertextBody, $sessionState->getLocalIdentityKey(), $sessionState->getRemoteIdentityKey());
        $ciphertextMessage = new WhisperMessage($sessionVersion, $messageKeys->getMacKey(), $senderEphemeral, $chainKey->getIndex(), $previousCounter, $ciphertextBody, $this->sessionStore->getIdentityKeyPair(), $sessionState->getRemoteIdentityKey());

        if ($sessionState->hasUnacknowledgedPreKeyMessage()) {
            $items = $sessionState->getUnacknowledgedPreKeyMessageItems();
            $localRegistrationid = $sessionState->getLocalRegistrationId();
            $ciphertextMessage = new PreKeyWhisperMessage($sessionVersion, $localRegistrationid, $items->getPreKeyId(), $items->getSignedPreKeyId(), $items->getBaseKey(), $sessionState->getLocalIdentityKey(), $ciphertextMessage);

            $sessionState->clearUnacknowledgedPreKeyMessage(); // Danny
        }

        $sessionState->setSenderChainKey($chainKey->getNextChainKey());
        $sessionRecord->setState($sessionState);
        $this->sessionStore->storeSession($this->recipientId, $this->deviceId, $sessionRecord);

        return $ciphertextMessage;
    }

    public function decryptMsg($ciphertext)
    {
        // :type ciphertext: WhisperMessage
        if (!$this->sessionStore->containsSession($this->recipientId, $this->deviceId)) {
            throw new NoSessionException('No session for: '.$this->recipientId.', '.$this->deviceId);
        }

        $sessionRecord = $this->sessionStore->loadSession($this->recipientId, $this->deviceId);
        $plaintext = $this->decryptWithSessionRecord($sessionRecord, $ciphertext);

        $this->sessionStore->storeSession($this->recipientId, $this->deviceId, $sessionRecord);

        /*
         * if sys.version_info >= (3,0):
         *      return plaintext.decode()
         */
        return $plaintext;
    }

    public function decryptPkmsg($ciphertext)
    {
        // :type ciphertext: PreKeyWhisperMessage
        $sessionRecord = $this->sessionStore->loadSession($this->recipientId, $this->deviceId);
        $unsignedPreKeyId = $this->sessionBuilder->process($sessionRecord, $ciphertext);

        $plaintext = $this->decryptWithSessionRecord($sessionRecord, $ciphertext->getWhisperMessage());

        //callback.handlePlaintext(plaintext);
        $this->sessionStore->storeSession($this->recipientId, $this->deviceId, $sessionRecord);

        if (null !== $unsignedPreKeyId) {
            $this->preKeyStore->removePreKey($unsignedPreKeyId);
        }
        /*
        if sys.version_info >= (3, 0):
            return plaintext.decode()
        */
        return $plaintext;
    }

    public function decryptWithSessionRecord($sessionRecord, $cipherText)
    {
        /*
        :type sessionRecord: SessionRecord
        :type cipherText: WhisperMessage
        */

        $previousStates = $sessionRecord->getPreviousSessionStates();
        $exceptions = [];

        try {
            $sessionState = new SessionState($sessionRecord->getSessionState());
            $plaintext = $this->decryptWithSessionState($sessionState, $cipherText);
            $sessionRecord->setState($sessionState);

            return $plaintext;
        } catch (InvalidMessageException $e) {
            echo $e->getMessage()."\n";
            $exceptions[] = $e;
        }

        for ($i = 0; $i < \count($previousStates); ++$i) {
            $previousState = $previousStates[$i];

            try {
                $promotedState = new SessionState($previousState);
                $plaintext = $this->decryptWithSessionState($promotedState, $cipherText);
                $sessionRecord->removePreviousSessionStateAt($i); // del $previousStates[$i]
                $sessionRecord->promoteState($promotedState);

                return $plaintext;
            } catch (InvalidMessageException $e) {
                echo $e->getMessage()."\n";
                $exceptions[] = $e;
            }
        }

        throw new InvalidMessageException('No valid sessions', $exceptions);
    }

    public function decryptWithSessionState($sessionState, $ciphertextMessage)
    {
        if (!$sessionState->hasSenderChain()) {
            throw new InvalidMessageException('Uninitialized session!');
        }

        if ($ciphertextMessage->getMessageVersion() !== $sessionState->getSessionVersion()) {
            throw new InvalidMessageException('Message version '.$ciphertextMessage->getMessageVersion().', but session version '.$sessionState->getSessionVersion());
        }

        $messageVersion = $ciphertextMessage->getMessageVersion();
        $theirEphemeral = $ciphertextMessage->getSenderRatchetKey();
        $counter = $ciphertextMessage->getCounter();
        $chainKey = $this->getOrCreateChainKey($sessionState, $theirEphemeral);
        $messageKeys = $this->getOrCreateMessageKeys($sessionState, $theirEphemeral, $chainKey, $counter);

        $ciphertextMessage->verifyMac($messageVersion, $sessionState->getRemoteIdentityKey(), $sessionState->getLocalIdentityKey(), $messageKeys->getMacKey());

        $plaintext = $this->getPlaintext($messageVersion, $messageKeys, $ciphertextMessage->getBody());
        $sessionState->clearUnacknowledgedPreKeyMessage();

        return $plaintext;
    }

    public function getOrCreateChainKey($sessionState, $ECPublicKey_theirEphemeral)
    {
        $theirEphemeral = $ECPublicKey_theirEphemeral;
        if ($sessionState->hasReceiverChain($theirEphemeral)) {
            return $sessionState->getReceiverChainKey($theirEphemeral);
        }
        $rootKey = $sessionState->getRootKey();

        $ourEphemeral = $sessionState->getSenderRatchetKeyPair();
        $receiverChain = $rootKey->createChain($theirEphemeral, $ourEphemeral);
        $ourNewEphemeral = Curve::generateKeyPair();
        $senderChain = $receiverChain[0]->createChain($theirEphemeral, $ourNewEphemeral);

        $sessionState->setRootKey($senderChain[0]);
        $sessionState->addReceiverChain($theirEphemeral, $receiverChain[1]);
        $sessionState->setPreviousCounter(\max($sessionState->getSenderChainKey()->getIndex() - 1, 0));
        $sessionState->setSenderChain($ourNewEphemeral, $senderChain[1]);

        return $receiverChain[1];
    }

    public function getOrCreateMessageKeys($sessionState, $ECPublicKey_theirEphemeral, $chainKey, $counter)
    {
        $theirEphemeral = $ECPublicKey_theirEphemeral;
        if ($chainKey->getIndex() > $counter) {
            if ($sessionState->hasMessageKeys($theirEphemeral, $counter)) {
                return $sessionState->removeMessageKeys($theirEphemeral, $counter);
            }
            throw new DuplicateMessageException('Received message '.'with old counter: '.$chainKey->getIndex().' '.$counter);
        }
        if ($counter - $chainKey->getIndex() > 2000) {
            throw new InvalidMessageException('Over 2000 messages into the future!');
        }

        while ($chainKey->getIndex() < $counter) {
            $messageKeys = $chainKey->getMessageKeys();
            $sessionState->setMessageKeys($theirEphemeral, $messageKeys);
            $chainKey = $chainKey->getNextChainKey();
        }
        $sessionState->setReceiverChainKey($theirEphemeral, $chainKey->getNextChainKey());

        return $chainKey->getMessageKeys();
    }

    public function getCiphertext($version, $messageKeys, $plainText)
    {
        /*
        :type version: int
        :type messageKeys: MessageKeys
        :type  plainText: bytearray
        */
        $cipher = null;

        if ($version >= 3) {
            $cipher = $this->getCipher($messageKeys->getCipherKey(), $messageKeys->getIv());
        } else {
            $cipher = $this->getCipher_v2($messageKeys->getCipherKey(), $messageKeys->getCounter());
        }

        return $cipher->encrypt($plainText);
    }

    public function getPlaintext($version, $messageKeys, $cipherText)
    {
        $cipher = null;

        if ($version >= 3) {
            $cipher = $this->getCipher($messageKeys->getCipherKey(), $messageKeys->getIv());
        } else {
            $cipher = $this->getCipher_v2($messageKeys->getCipherKey(), $messageKeys->getCounter());
        }

        return $cipher->decrypt($cipherText);
    }

    public function getCipher($key, $iv)
    {
        //Cipher.getInstance("AES/CBC/PKCS5Padding");
        //cipher = AES.new(key, AES.MODE_CBC, IV = iv)
        //return cipher
        return new AESCipher($key, $iv);
    }

    public function getCipher_v2($key, $counter)
    {
        /* #AES/CTR/NoPadding
        #counterbytes = struct.pack('>L', counter) + (b'\x00' * 12)
        #counterint = struct.unpack(">L", counterbytes)[0]
        #counterint = int.from_bytes(counterbytes, byteorder='big')
        ctr=Counter.new(128, initial_value= counter)

        #cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ivBytes = bytearray(16)
        ByteUtil.intToByteArray(ivBytes, 0, counter)

        cipher = AES.new(key, AES.MODE_CTR, IV = bytes(ivBytes), counter=ctr)

        return cipher;*/
        return new AESCipher($key, null, 2, new CryptoCounter(128, $counter));
        throw new \Exception('To be implemented.');
    }
}

class CryptoCounter
{
    protected $size;
    protected $val;

    public function __construct($size = 128, $init_val = 0)
    {
        $this->val = $init_val;
        if (!\in_array($size, [128, 192, 256], true)) {
            throw new \Exception('Counter size cannot be other than 128,192 or 256 bits');
        }
        $this->size = $size / 8;
    }

    public function Next()
    {
        $b = \array_reverse(\unpack('C*', \pack('L', $this->val)));
        //byte array to string
        $ctr_str = \implode('', \array_map('chr', $b));
        // create 16 byte IV from counter
        $ctrVal = \str_repeat("\x0", ($this->size - 4)).$ctr_str;
        ++$this->val;

        return $ctrVal;
    }
}
