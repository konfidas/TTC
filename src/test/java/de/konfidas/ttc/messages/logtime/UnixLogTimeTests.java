package de.konfidas.ttc.messages.logtime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.security.SecureRandom;
import java.security.Security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.BeforeEach.*;

public class UnixLogTimeTests {
    static SecureRandom rnd;

    @BeforeEach
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
        rnd = new SecureRandom();
    }

    @Test
    public void testEqualUnixTimes(){
        int time =  rnd.nextInt();

        UnixLogTime t1 = new UnixLogTime(time);
        UnixLogTime t2 = new UnixLogTime(time);

        assertTrue(t1.equals(t2));
    }

    @Test
    public void testUnixTimesOffByOne(){
        int time =  rnd.nextInt();

        UnixLogTime t1 = new UnixLogTime(time);
        UnixLogTime t2 = new UnixLogTime(time+1);

        assertTrue(t1.wasNotAfter(t2));
        assertFalse(t2.wasNotAfter(t1));
    }

}
