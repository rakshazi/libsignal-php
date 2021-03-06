<?php

declare(strict_types=1);

namespace Libsignal\Tests;

//from axolotl.state.sessionstore import SessionStore
//from axolotl.state.sessionrecord import SessionRecord
use Libsignal\state\SessionRecord;
use Libsignal\state\SessionStore;

//if someone asks why the separator is __putaidea__ for the key,is because was the first thing i listened around when i was thinking how to implement the tuple in php
class InMemorySessionStore extends SessionStore
{
    protected $sessions;

    public function __construct()
    {
        $this->sessions = [];
    }

    public function loadSession($recepientId, $deviceId)
    {
        if ($this->containsSession($recepientId, $deviceId)) {
            return new SessionRecord(null, $this->sessions[$this->Key($recepientId, $deviceId)]);
        }

        return new SessionRecord();
    }

    public function getSubDeviceSessions($recepientId)
    {
        $deviceIds = [];
        foreach (\array_keys($this->sessions) as $key) {
            $k = $this->SplitKey($key);
            if ($k[0] === $recepientId) {
                $deviceIds[] = $k[1];
            }
        }

        return $deviceIds;
    }

    public function storeSession($recepientId, $deviceId, $sessionRecord): void
    {
        $this->sessions[$this->Key($recepientId, $deviceId)] = $sessionRecord->serialize();
    }

    public function containsSession($recepientId, $deviceId)
    {
        return isset($this->sessions[$this->Key($recepientId, $deviceId)]);
    }

    public function deleteSession($recepientId, $deviceId): void
    {
        unset($this->sessions[$this->Key($recepientId, $deviceId)]);
    }

    public function deleteAllSessions($recepientId): void
    {
        foreach (\array_keys($this->sessions) as $key) {
            $k = $this->SplitKey($key);
            if ($k[0] === $recepientId) {
                unset($this->sessions[$key]);
            }
        }
    }

    private function Key($recepientId, $deviceId)
    {
        return $recepientId.'__putaidea__'.$deviceId;
    }

    private function SplitKey($key)
    {
        return \explode('__putaidea__', $key);
    }
}
