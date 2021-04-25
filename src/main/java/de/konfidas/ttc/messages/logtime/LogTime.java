package de.konfidas.ttc.messages.logtime;

public abstract class LogTime{

    public enum Type{
        UNIX, GENERALIZED, UTC;
    }

    public abstract Type getType();
}
