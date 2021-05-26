package br.ufrn.sti.web.filters.xss.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.owasp.esapi.ESAPI;

/**
 * @author Raphael Medeiros (raphael.medeiros@gmail.com)
 * @since 06/02/2019
 */
public class XSSUtils {

	private Logger logger = Logger.getLogger(XSSUtils.class);

	private static Pattern[] patterns = new Pattern[] {
			// Script fragments
			Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
			// src='...'
			Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'",
					Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
			Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"",
					Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
			// lonely script tags
			Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
			Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
			// eval(...)
			Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
			// expression(...)
			Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
			// javascript:...
			Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
			// vbscript:...
			Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
			// onload(...)=...
			Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL) };

	public boolean hasXSS(Map map) {
		logger.debug(String.format("Map value...........: %s", map));

		if (map != null) {
			Iterator iter = map.keySet().iterator();

			while (iter.hasNext()) {
				String key = (String) iter.next();

				String[] values = (String[]) map.get(key);

				if (values != null) {
					logger.debug(String.format("Values..............: %s", Arrays.toString(values)));

					for (int i = 0; i < values.length; i++) {
						if (hasXSS(values[i])) {
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	public boolean hasXSS(String value) {
		logger.debug(String.format("Value to check XSS..: %s", value));

		if (value != null) {
			for (Pattern scriptPattern : patterns) {
				if (scriptPattern.matcher(value).find()) {
					return true;
				}
			}
		}

		return false;
	}

	public String stripXSS(String value) {
		logger.debug(String.format("Value to Strip XSS..: %s", value));

		if (value != null) {
			// NOTE: It's highly recommended to use the ESAPI library and uncomment the
			// following line to avoid encoded attacks.
			value = ESAPI.encoder().canonicalize(value);
			logger.debug(String.format("Value after ESAPI...: %s", value));

			// Avoid null characters
			value = value.replaceAll("\0", "");
			logger.debug(String.format("Value after NULL....: %s", value));

			// Remove all sections that match a pattern
			for (Pattern scriptPattern : patterns) {
				logger.debug(String.format("Pattern.............: %s", scriptPattern.toString()));

				value = scriptPattern.matcher(value).replaceAll("");
				logger.debug(String.format("Value after PATTERN.: %s", value));
			}
		}

		return value;
	}

	public Map getSafeParameterMap(Map map) {
		logger.debug(String.format("Map value...........: %s", map));

		Map newMap = new HashMap();

		if (map != null) {
			Iterator iter = map.keySet().iterator();

			while (iter.hasNext()) {
				String key = (String) iter.next();

				String[] oldValues = (String[]) map.get(key);

				if (oldValues != null && oldValues.length > 0) {
					logger.debug(String.format("OLD values..........: %s", Arrays.toString(oldValues)));

					String[] newValues = new String[oldValues.length];
					logger.debug(String.format("NEW values..........: %s", Arrays.toString(newValues)));

					for (int i = 0; i < oldValues.length; i++) {
						newValues[i] = stripXSS(oldValues[i]);
					}

					newMap.put(key, newValues);
				}

			}
		}

		logger.debug(String.format("NEW Map.............: %s", newMap));

		return Collections.unmodifiableMap(newMap);
	}

}
