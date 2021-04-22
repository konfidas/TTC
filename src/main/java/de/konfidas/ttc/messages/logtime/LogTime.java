package de.konfidas.ttc.messages.logtime;

public abstract class LogTime{



    public enum Type{
        UNIX, GENERALIZED, UTC;
    }

    public boolean wasNotAfter(LogTime logTime){
        return this.getTime() <= logTime.getTime();
    }

    public abstract long getTime();
    public abstract Type getType();
}
