package br.ufrn.sti.web.filters.xss;

import br.ufrn.sti.web.filters.xss.util.XSSUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.*;

/**
 * @author Raphael Medeiros (raphael.medeiros@gmail.com)
 * @author Arlindo Rodrigues (arlindonatal@gmail.com)
 *
 * @since 04/02/2019
 */
public class XSSFilter implements Filter {

	private List<String> excludedUrls = new ArrayList<String>();
	private Set<String> urls = new HashSet<String>();
	private XSSUtils xssUtils = new XSSUtils();

	private static final String INIT_PARAM_LOGGING = "logging";
	private static final String INIT_PARAM_BEHAVIOR = "behavior";
	private static final String INIT_PARAM_FORWARDTO = "forwardTo";

	private static final String BEHAVIOR_PROTECT = "protect";
	private static final String BEHAVIOR_THROW = "throw";
	private static final String BEHAVIOR_FORWARD = "forward";

	private FilterConfig filterConfig;

	private Logger logger = Logger.getLogger(this.getClass());

	private static long attempts = 0;

	@Override
	public void init(FilterConfig filterConfig){
		this.filterConfig = filterConfig;
		String excludePattern = filterConfig.getInitParameter("excludedUrls");
		if (excludePattern != null && !excludePattern.isEmpty()) {
			excludedUrls = Arrays.asList(excludePattern.split(","));
			for (String excludeUrl : excludedUrls)
				urls.add(excludeUrl.replaceAll("\\s", "").replaceAll("\\n", "").replaceAll("\\r", "").replaceAll("\\t", "").replaceAll(" ", ""));
		}
	}

	@Override
	public void destroy() {
		// implementacao nao necessaria
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain filterChain)
			throws IOException, ServletException {

		HttpServletRequest httpServletRequest = (HttpServletRequest) req;
		try {

			String path = httpServletRequest.getRequestURI();
			path = path.substring(httpServletRequest.getContextPath().length());

			if (!excludedUrls.contains(path)) {

				ResettableStreamHttpServletRequest originalRequest = new ResettableStreamHttpServletRequest(httpServletRequest);
				String body = IOUtils.toString(originalRequest.getReader());
				boolean isUnsafeParams = xssUtils.hasXSS(originalRequest.getParameterMap());
				boolean isUnsafeBody = xssUtils.hasXSS(body);

				if (isUnsafeParams || isUnsafeBody){

					String pLogging = filterConfig.getInitParameter(INIT_PARAM_LOGGING);
					if (pLogging != null && pLogging.equalsIgnoreCase("true")) {
						registrarLogOcorrenciaParametrosSuspeitos(originalRequest, body);
					}

					String behavior = filterConfig.getInitParameter(INIT_PARAM_BEHAVIOR);
					String forwardTo = filterConfig.getInitParameter(INIT_PARAM_FORWARDTO);

					if (!isUnsafeBody && behavior != null && behavior.equalsIgnoreCase(BEHAVIOR_PROTECT)) {
						originalRequest.resetInputStream();
						filterChain.doFilter(new XSSRequestWrapper(originalRequest), resp);
					} else if (behavior != null && behavior.equalsIgnoreCase(BEHAVIOR_FORWARD) && forwardTo != null) {
						HttpServletResponse currentResponse = (HttpServletResponse) resp;
						currentResponse.setStatus(HttpServletResponse.SC_CONTINUE);
						RequestDispatcher dd = originalRequest.getRequestDispatcher(forwardTo);
						dd.forward(originalRequest, currentResponse);
					} else {
						throw new ServletException("XSS Injection Detected!");
					}

				} else {
					originalRequest.resetInputStream();
					filterChain.doFilter(originalRequest, resp);
				}

			} else {
				filterChain.doFilter(httpServletRequest, resp);
			}

		} catch (Exception e) {
			logger.error("Erro no tratamento de XSS.", e);
			filterChain.doFilter(req, resp);
		}

	}

	private static class ResettableStreamHttpServletRequest extends HttpServletRequestWrapper {

		private byte[] rawData;
		private HttpServletRequest request;
		private ResettableServletInputStream servletStream;

		public ResettableStreamHttpServletRequest(HttpServletRequest request) {
			super(request);
			this.request = request;
			this.servletStream = new ResettableServletInputStream();
		}


		public void resetInputStream() {
			servletStream.stream = new ByteArrayInputStream(rawData);
		}

		@Override
		public ServletInputStream getInputStream() throws IOException {
			if (rawData == null) {
				rawData = IOUtils.toByteArray(this.request.getReader());
				servletStream.stream = new ByteArrayInputStream(rawData);
			}
			return servletStream;
		}

		@Override
		public BufferedReader getReader() throws IOException {
			if (rawData == null) {
				rawData = IOUtils.toByteArray(this.request.getReader());
				servletStream.stream = new ByteArrayInputStream(rawData);
			}
			return new BufferedReader(new InputStreamReader(servletStream));
		}


		private class ResettableServletInputStream extends ServletInputStream {

			private InputStream stream;

			@Override
			public int read() throws IOException {
				return stream.read();
			}
		}
	}

	private void registrarLogOcorrenciaParametrosSuspeitos(HttpServletRequest originalRequest, String body) {
		StringBuilder sb = new StringBuilder();
		sb.append("\nPossible XSS injection attempt #" + (++attempts) + " at " + new java.util.Date());
		sb.append("\nRemote Address: " + originalRequest.getRemoteAddr());
		sb.append("\nRemote User: " + originalRequest.getRemoteUser());
		sb.append("\nSession Id: " + originalRequest.getRequestedSessionId());
		sb.append("\nURI: " + originalRequest.getContextPath() + originalRequest.getRequestURI());
		sb.append("\nParameters via " + originalRequest.getMethod());
		Map paramMap = originalRequest.getParameterMap();
		if (paramMap != null) {
			for (Iterator iter = paramMap.keySet().iterator(); iter.hasNext(); ) {
				String paramName = (String) iter.next();
				String[] paramValues = originalRequest.getParameterValues(paramName);
				sb.append("\n\t" + paramName + " = ");
				for (int j = 0; j < paramValues.length; j++) {
					sb.append(paramValues[j]);
					if (j < paramValues.length - 1) {
						sb.append(" , ");
					}
				}
			}
		}

		if (body != null && !body.isEmpty())
			sb.append("\nBody: " + body);

		logger.error(sb);
	}
}
