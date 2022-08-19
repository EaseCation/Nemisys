package org.itxtech.nemisys.utils;

/**
 * org.itxtech.nemisys.utils
 * ===============
 * author: boybook
 * EaseCation Network Project
 * CodeFunCore
 * ===============
 */
public final class MathUtil {

    /**
     * 求给定双精度数组中值的最大值
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果,如果输入值不合法，返回为-1
     */
    public static double getMax(double[] inputData) {
        if (inputData == null || inputData.length == 0)
            return -1;
        double max = inputData[0];
        for (double inputDatum : inputData) {
            if (max < inputDatum)
                max = inputDatum;
        }
        return max;
    }

    /**
     * 求求给定双精度数组中值的最小值
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果,如果输入值不合法，返回为-1
     */
    public static double getMin(double[] inputData) {
        if (inputData == null || inputData.length == 0)
            return -1;
        double min = inputData[0];
        for (double inputDatum : inputData) {
            if (min > inputDatum)
                min = inputDatum;
        }
        return min;
    }

    /**
     * 求给定双精度数组中值的和
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果
     */
    public static double getSum(double[] inputData) {
        if (inputData == null || inputData.length == 0)
            return -1;
        double sum = 0;
        for (double inputDatum : inputData) {
            sum = sum + inputDatum;
        }

        return sum;

    }

    /**
     * 求给定双精度数组中值的数目
     *
     * @param inputData 输入数据数组
     * @return 运算结果
     */
    public static int getCount(double[] inputData) {
        if (inputData == null)
            return -1;

        return inputData.length;
    }

    /**
     * 求给定双精度数组中值的平均值
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果
     */
    public static double getAverage(double[] inputData) {
        if (inputData == null || inputData.length == 0)
            return -1;
        int len = inputData.length;
        double result;
        result = getSum(inputData) / len;

        return result;
    }

    /**
     * 求给定双精度数组中值的平方和
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果
     */
    public static double getSquareSum(double[] inputData) {
        if(inputData==null||inputData.length==0)
            return -1;
        double sqrsum = 0.0;
        for (double inputDatum : inputData) {
            sqrsum = sqrsum + inputDatum * inputDatum;
        }

        return sqrsum;
    }

    /**
     * 求给定双精度数组中值的方差
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果
     */
    public static double getVariance(double[] inputData) {
        int count = getCount(inputData);
        double sqrsum = getSquareSum(inputData);
        double average = getAverage(inputData);
        double result;
        result = (sqrsum - count * average * average) / count;

        return result;
    }

    /**
     * 求给定双精度数组中值的标准差
     *
     * @param inputData
     *            输入数据数组
     * @return 运算结果
     */
    public static double getStandardDiviation(double[] inputData) {
        double result;
        //绝对值化很重要
        result = Math.sqrt(Math.abs(getVariance(inputData)));

        return result;

    }

}
