<?php

declare(strict_types=1);

namespace Libsignal\logging;

class Log extends AxolotlLogger
{
    public static function verbose($tag, $msg): void // [String tag, String msg]
    {
        self::writeLog(self::VERBOSE, $tag, $msg);
    }

    public static function verboseException($tag, $msg, $tr): void // [String tag, String msg, Throwable tr]
    {
        self::writeLog(self::VERBOSE, $tag, (($msg.'\n').self::getStackTraceString($tr)));
    }

    public static function debug($tag, $msg): void // [String tag, String msg]
    {
        self::writeLog(self::DEBUG, $tag, $msg);
    }

    public static function debugException($tag, $msg, $tr): void // [String tag, String msg, Throwable tr]
    {
        self::writeLog(self::DEBUG, $tag, (($msg.'\n').self::getStackTraceString($tr)));
    }

    public static function info($tag, $msg): void // [String tag, String msg]
    {
        self::writeLog(self::INFO, $tag, $msg);
    }

    public static function infoException($tag, $msg, $tr): void // [String tag, String msg, Throwable tr]
    {
        self::writeLog(self::INFO, $tag, (($msg.'\n').self::getStackTraceString($tr)));
    }

    public static function warn($tag, $msg): void // [String tag, String msg]
    {
        self::writeLog(self::WARN, $tag, $msg);
    }

    public static function warnException($tag, $msg, $tr): void // [String tag, String msg, Throwable tr]
    {
        self::writeLog(self::WARN, $tag, (($msg.'\n').self::getStackTraceString($tr)));
    }

    public static function warnShortException($tag, $tr): void // [String tag, Throwable tr]
    {
        self::writeLog(self::WARN, $tag, self::getStackTraceString($tr));
    }

    public static function error($tag, $msg): void // [String tag, String msg]
    {
        self::writeLog(self::ERROR, $tag, $msg);
    }

    public static function errorException($tag, $msg, $tr): void // [String tag, String msg, Throwable tr]
    {
        self::writeLog(self::ERROR, $tag, (($msg.'\n').self::getStackTraceString($tr)));
    }

    //old function name log

    public static function writeLog($priority, $tag, $msg): void // [int priority, String tag, String msg]
    {
        $logger = AxolotlLoggerProvider::getProvider();
        if ((null !== $logger)) {
            $logger->log($priority, $tag, $msg);
        }
    }

    protected static function getStackTraceString($tr) // [Throwable tr]
    {
        if ($tr instanceof Exception) {
            return $tr->getTrace();
        }

        return '';
    }
}
