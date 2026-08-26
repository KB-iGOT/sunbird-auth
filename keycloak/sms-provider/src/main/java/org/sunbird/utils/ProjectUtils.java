package org.sunbird.utils;

import java.security.SecureRandom;
import java.util.Random;

public class ProjectUtils {

	public static String nextString(int length, String symbols) {

		if (length < 1)
			throw new IllegalArgumentException();
		if (symbols.length() < 2)
			throw new IllegalArgumentException();
		Random random = new SecureRandom();
		char[] symbolsArr = symbols.toCharArray();
		char[] buf = new char[length];

		for (int idx = 0; idx < buf.length; ++idx) {
			buf[idx] = symbolsArr[random.nextInt(symbolsArr.length)];
		}
		return new String(buf);
	}
}
