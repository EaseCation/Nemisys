package org.itxtech.nemisys.math;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class NemisysMath {

    public static double round(double d) {
        return round(d, 0);
    }

    public static double round(double d, int precision) {
        return ((double) Math.round(d * Math.pow(10, precision))) / Math.pow(10, precision);
    }

}
