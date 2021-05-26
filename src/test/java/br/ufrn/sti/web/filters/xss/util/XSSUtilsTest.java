package br.ufrn.sti.web.filters.xss.util;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Raphael Medeiros (raphael.medeiros@gmail.com)
 *
 * @since 08/02/2019
 */
public class XSSUtilsTest {

	private Logger logger = Logger.getLogger(XSSUtilsTest.class);

	private XSSUtils xssUtils;

	@Before
	public void setUp() throws Exception {
		xssUtils = new XSSUtils();
	}

	@Test
	public void stripXSSNullValue() {
		logger.info("Testing NULL value...");

		String value = xssUtils.stripXSS(null);

		Assert.assertNull(value);
	}

	@Test
	public void stripXSSEmptyValue() {
		logger.info("Testing EMPTY value...");

		String value = xssUtils.stripXSS("");
		Assert.assertTrue(value.isEmpty());
	}

	@Test
	public void stripXSSWhiteSpaceValue() {
		logger.info("Testing WHITE SPACE value...");

		String value = xssUtils.stripXSS(" ");
		Assert.assertTrue(" ".equalsIgnoreCase(value));
	}

	@Test
	public void getSafeParameterMapNullValue() {
		logger.info("Testing NULL value...");

		Map map = xssUtils.getSafeParameterMap(null);

		Assert.assertNotNull(map);
		Assert.assertTrue((map instanceof Map));
	}

	@Test
	public void getSafeParameterMapEmptyValue() {
		logger.info("Testing EMPTY value...");

		Map map = xssUtils.getSafeParameterMap(new HashMap());

		Assert.assertNotNull(map);
		Assert.assertTrue((map instanceof Map));
	}
}