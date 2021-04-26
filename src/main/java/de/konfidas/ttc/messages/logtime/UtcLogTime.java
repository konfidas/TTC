package de.konfidas.ttc.messages.logtime;

public class UtcLogTime extends LogTime{
    String time;

    public UtcLogTime(String time) {
        this.time = time;
    }

    @Override
    public String toString(){
        return time;
    }

    @Override
    public Type getType() {
        return Type.UTC;
    }
}
