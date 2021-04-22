package de.konfidas.ttc.messages.logtime;

public class UnixLogTime extends LogTime {
    int time;
    public UnixLogTime(int time) {
        this.time = time;
    }

    @Override
    public String toString(){
        return Integer.valueOf(time).toString();
    }

    @Override
    public long getTime() {
        return time*1000;
    }

    @Override
    public Type getType() {
        return Type.UNIX;
    }
    public int getValue(){
        return time;
    }
}
