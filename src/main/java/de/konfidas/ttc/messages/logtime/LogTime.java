package de.konfidas.ttc.messages.logtime;

public abstract class LogTime{



    public enum Type{
        UNIX, GENERALIZED, UTC
    }

    public boolean wasNotAfter(LogTime logTime){
        return this.getTime() <= logTime.getTime();
    }

    @Override
    public boolean equals(Object t){
        if(t instanceof LogTime) {
            return ((LogTime)t).wasNotAfter(this) && this.wasNotAfter((LogTime)t);
        }else{
            return false;
        }
    }

    public abstract long getTime();
    public abstract Type getType();
}
