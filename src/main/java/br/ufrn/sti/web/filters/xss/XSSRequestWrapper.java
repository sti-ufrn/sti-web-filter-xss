package br.ufrn.sti.web.filters.xss;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Arrays;
import java.util.Map;

import br.ufrn.sti.web.filters.xss.util.XSSUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;

/**
 * @author Raphael Medeiros (raphael.medeiros@gmail.com)
 *
 * @since 04/02/2019
 */
public class XSSRequestWrapper extends HttpServletRequestWrapper {

	private Logger logger = Logger.getLogger(XSSRequestWrapper.class);

	private XSSUtils xssUtils = new XSSUtils();

	private HttpServletRequest originalRequest;

	private Map safeParameterMap;

	public XSSRequestWrapper(HttpServletRequest servletRequest) {
		super(servletRequest);

		this.originalRequest = servletRequest;
	}

	public Map getParameterMap() {
		if (safeParameterMap == null) {
			Map originalParameterMap = originalRequest.getParameterMap();
			safeParameterMap = xssUtils.getSafeParameterMap(originalParameterMap);
		}

		logger.debug(String.format("Safe Parameter Map: %s", safeParameterMap));

		return safeParameterMap;
	}

	public String[] getParameterValues(String parameter) {
		logger.debug(String.format("Parameter: %s", parameter));

		String[] values = (String[]) getParameterMap().get(parameter);

		if (values != null && values.length > 0) {
			logger.debug(String.format("Values...: %s", Arrays.toString(values)));

			return values;
		}

		return ArrayUtils.EMPTY_STRING_ARRAY;
	}

	public String getParameter(String parameter) {
		logger.debug(String.format("Parameter: %s", parameter));

		String[] values = getParameterValues(parameter);

		if (values != null && values.length > 0) {
			logger.debug(String.format("Values...: %s", Arrays.toString(values)));

			return values[0];
		} else {
			return null;
		}
	}

	@Override
	public String getHeader(String name) {
		logger.debug(String.format("Header: %s", name));

		String value = super.getHeader(name);
		logger.debug(String.format("Value.: %s", value));

		return xssUtils.stripXSS(value);
	}
}
