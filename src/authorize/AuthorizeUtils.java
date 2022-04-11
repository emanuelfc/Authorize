package authorize;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import utils.HttpService;
import utils.Parameter;

public class AuthorizeUtils
{	
	public static List<IParameter> getRequestCookies(IRequestInfo request)
	{
		Predicate<IParameter> predicate = (param) -> (param.getType() == IParameter.PARAM_COOKIE);
		return request.getParameters().stream().filter(predicate).collect(Collectors.toList());
	}
	
	public static List<IParameter> getRequestsCookies(IHttpRequestResponse[] messagesInfo)
	{
		List<IParameter> cookieList = new LinkedList<IParameter>();
		
		for(IHttpRequestResponse messageInfo: messagesInfo)
		{
			cookieList.addAll(AuthorizeUtils.getRequestCookies(messageInfo.getRequest()));
		}

		return cookieList;
	}
	
	public static List<IParameter> getRequestCookies(byte[] request)
	{
		return getRequestCookies(BurpExtender.helpers.analyzeRequest(request));
	}
	
	public static List<IParameter> getResponseCookies(byte[] response)
	{
		return AuthorizeUtils.cookiesToParameters(BurpExtender.helpers.analyzeResponse(response).getCookies());
	}
	
	public static List<IParameter> getResponsesCookies(IHttpRequestResponse[] messagesInfo)
	{
		List<IParameter> cookieList = new LinkedList<IParameter>();
		
		for(IHttpRequestResponse messageInfo: messagesInfo)
		{
			cookieList.addAll(AuthorizeUtils.getResponseCookies(messageInfo.getResponse()));
		}
		
		return cookieList;
	}
	
	public static List<Parameter> convertBurpParametersToParameters(List<IParameter> parameters)
	{
		List<Parameter> comparableParameters = new LinkedList<Parameter>();
		
		for(IParameter burpParameter: parameters)
		{
			comparableParameters.add(new Parameter(burpParameter));
		}
		
		return comparableParameters;
	}
	
	public static IParameter cookieToParameter(ICookie cookie)
	{
		return BurpExtender.helpers.buildParameter(cookie.getName(), cookie.getValue(), IParameter.PARAM_COOKIE);
	}
	
	public static List<IParameter> cookiesToParameters(List<ICookie> cookies)
	{
		List<IParameter> cookieList = new LinkedList<IParameter>();
		
		for(ICookie cookie: cookies)
		{
			cookieList.add(AuthorizeUtils.cookieToParameter(cookie));
		}
		
		return cookieList;
	}
	
	public static IParameter cookieToParameter(String cookie)
	{
		String[] cookieParts = cookie.split("=", 0);
		
		String name = "";
		String value = "";
		
		if(cookieParts.length > 0)
		{
			name = cookieParts[0].trim();
		}
		if(cookieParts.length == 2)
		{
			value = cookieParts[1].trim();
		}

		return BurpExtender.helpers.buildParameter(name, value, IParameter.PARAM_COOKIE);
	}
	
	public static List<IParameter> cookiesToParameters(String cookies)
	{
		List<IParameter> cookiesList = new LinkedList<IParameter>();
		
		for(String cookie: cookies.split(";"))
		{
			IParameter cookieParam = AuthorizeUtils.cookieToParameter(cookie);
			
			if(cookieParam != null)
			{
				cookiesList.add(cookieParam);
			}
		}
		
		return cookiesList;
	}
	
	private static byte[] copyBody(byte[] message, int bodyOffset)
	{
		return Arrays.copyOfRange(message, bodyOffset, message.length);
	}
	
	public static byte[] copyRequestBody(byte[] request)
	{
		return copyBody(request, BurpExtender.helpers.analyzeRequest(request).getBodyOffset());
	}
	
	public static byte[] copyResponseBody(byte[] response)
	{	
		return copyBody(response, BurpExtender.helpers.analyzeResponse(response).getBodyOffset());
	}
	
	public static byte[] addHeader(byte[] request, String header)
	{
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		
		List<String> headers = analyzedRequest.getHeaders();
		headers.add(header);
		byte[] body = copyRequestBody(request);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	public static byte[] addOrReplaceHeader(byte[] request, String header)
	{
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		
		List<String> headers = analyzedRequest.getHeaders();
		
		String targetHeader = headers.stream().filter((s) -> (getHeaderName(s).equals(getHeaderName(header)))).findAny().get();
		if(targetHeader != null)
		{
			headers.remove(targetHeader);
		}
		
		headers.add(targetHeader);
		
		byte[] body = copyRequestBody(request);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	public static byte[] replaceHeader(byte[] request, String headerInput, boolean isRegex, String newHeader)
	{
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		
		Predicate<String> isHeader;
		if(isRegex) isHeader = (header) -> {return Pattern.matches(headerInput, header);};
		else isHeader = (header) -> {return header.equals(headerInput);};
		
		List<String> headers = analyzedRequest.getHeaders();
		List<String> newHeaders = new LinkedList<String>();
		
		for(String header: headers)
		{
			if(isHeader.test(header))
			{
				header = newHeader;
			}
			
			newHeaders.add(header);
		}
		
		byte[] body = copyRequestBody(request);
		
		return BurpExtender.helpers.buildHttpMessage(newHeaders, body);
	}
	
	public static byte[] updateHeaderValue(byte[] request, String headerName, boolean isRegex, String newHeaderValue)
	{
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		
		Predicate<String> isHeader;
		if(isRegex) isHeader = (header) -> {return header.split(":").length == 2 && Pattern.matches(headerName, getHeaderName(header));};
		else isHeader = (header) -> {return header.split(":").length == 2 && getHeaderName(header).equals(headerName);};
		
		List<String> headers = analyzedRequest.getHeaders();
		List<String> newHeaders = new LinkedList<String>();
		
		for(String header: headers)
		{
			if(isHeader.test(header))
			{
				header = getHeaderName(header) + ": " + newHeaderValue;
			}
			
			newHeaders.add(header);
		}
		
		byte[] body = copyRequestBody(request);
		
		return BurpExtender.helpers.buildHttpMessage(newHeaders, body);
	}
	
	public static byte[] removeHeader(byte[] request, String header, boolean isRegex)
	{
		Predicate<String> predicate;
		if(isRegex) predicate = (requestHeader) -> (!Pattern.matches(header, requestHeader));
		else predicate = (requestHeader) -> (!requestHeader.equals(header));
		
		return removeHeader(request, predicate);
	}
	
	private static byte[] removeHeader(byte[] request, Predicate<String> predicate)
	{
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		List<String> remainingHeaders = analyzedRequest.getHeaders().stream().filter(predicate).collect(Collectors.toList());
		byte[] body = copyRequestBody(request);
		
		return BurpExtender.helpers.buildHttpMessage(remainingHeaders, body);
	}
	
	public static byte[] addParam(byte[] request, String name, String value, byte paramType)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);

		IParameter newParam = BurpExtender.helpers.buildParameter(name, value, paramType);
		newRequest = BurpExtender.helpers.addParameter(newRequest, newParam);
		
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = copyRequestBody(newRequest);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	public static byte[] updateParamName(byte[] request, String oldName, String newName, boolean isRegex, byte paramType)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		
		Predicate<IParameter> predicate;
		
		if(isRegex) predicate = (param) -> (Pattern.matches(oldName, param.getName()) && param.getType() == paramType);
		else predicate = (param) -> (oldName.equals(param.getName()) && param.getType() == paramType);

		IParameter oldParam = analyzedRequest.getParameters().stream().filter(predicate).findFirst().get();
		
		if(oldParam != null)
		{
			newRequest = BurpExtender.helpers.removeParameter(newRequest, oldParam);
			IParameter newParam = BurpExtender.helpers.buildParameter(newName, oldParam.getValue(), paramType);
			newRequest = BurpExtender.helpers.addParameter(newRequest, newParam);
		}
		
		analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = copyRequestBody(newRequest);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	public static byte[] updateParamValue(byte[] request, String name, String value, boolean isRegex, byte paramType)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		
		Predicate<IParameter> predicate;
		
		if(isRegex) predicate = (param) -> (Pattern.matches(name, param.getName()) && param.getType() == paramType);
		else predicate = (param) -> (name.equals(param.getName()) && param.getType() == paramType);

		IParameter oldParam = analyzedRequest.getParameters().stream().filter(predicate).findFirst().get();
		
		if(oldParam != null)
		{
			IParameter newParam = BurpExtender.helpers.buildParameter(oldParam.getName(), value, paramType);
			newRequest = BurpExtender.helpers.updateParameter(newRequest, newParam);
		}
		
		analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = copyRequestBody(newRequest);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	/*
	public static byte[] mergeCookiesToRequest(byte[] request, List<? extends IParameter> otherCookies)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);
		
		List<IParameter> requestCookies = getRequestCookies(newRequest);
		for(IParameter cookieParam: requestCookies)
		{
			newRequest = BurpExtender.helpers.removeParameter(newRequest, cookieParam);
		}
		
		Set<IParameter> allCookies = mergeCookies(requestCookies, otherCookies);
		for(IParameter cookieParam: allCookies)
		{
			newRequest = BurpExtender.helpers.addParameter(newRequest, cookieParam);
		}

		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = copyRequestBody(newRequest);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	*/
		
	public static byte[] removeParamByName(byte[] request, String name, boolean isRegex, byte paramType)
	{
		Predicate<IParameter> predicate;
		
		if(isRegex) predicate = (param) -> (Pattern.matches(name, param.getName()) && param.getType() == paramType);
		else predicate = (param) -> (name.equals(param.getName()) && param.getType() == paramType);
		
		return removeParamByPredicate(request, predicate);
	}
	
	public static byte[] removeParamByValue(byte[] request, String value, boolean isRegex, byte paramType)
	{
		Predicate<IParameter> predicate;
		
		if(isRegex) predicate = (param) -> (Pattern.matches(value, param.getValue()) && param.getType() == paramType);
		else predicate = (param) -> (value.equals(param.getValue()) && param.getType() == paramType);
		
		return removeParamByPredicate(request, predicate);
	}
	
	public static byte[] removeParamByPredicate(byte[] request, Predicate<IParameter> predicate)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);
		
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<IParameter> removableParams = analyzedRequest.getParameters().stream().filter(predicate).collect(Collectors.toList());
		
		for(IParameter param: removableParams)
		{
			newRequest = BurpExtender.helpers.removeParameter(newRequest, param);
		}
		
		analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = copyRequestBody(newRequest);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	public static byte[] updateRequest(byte[] request, String match, boolean isRegex, String replace)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);
		newRequest = replaceBytes(newRequest, match, isRegex, replace);
		
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = copyRequestBody(newRequest);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	public static byte[] updateRequestBody(byte[] request, String match, boolean isRegex, String replace)
	{
		byte[] newRequest = Arrays.copyOf(request, request.length);
		byte[] newBodyBytes = replaceBytes(copyRequestBody(newRequest), match, isRegex, replace);
		
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		List<String> headers = analyzedRequest.getHeaders();
		
		return BurpExtender.helpers.buildHttpMessage(headers, newBodyBytes);
	}
	
	public static byte[] replaceBytes(byte[] messageBytes, String match, boolean isRegex, String replace)
	{
		String messageString = BurpExtender.helpers.bytesToString(messageBytes);
		
		if(isRegex) messageString = messageString.replaceAll(match, replace);
		else messageString = messageString.replace(match, replace);
		
		return BurpExtender.helpers.stringToBytes(messageString);
	}
	
	public static IHttpRequestResponse makeHttpRequest(byte[] request) throws MalformedURLException
	{
		HttpService httpService = HttpService.buildFromURL(BurpExtender.helpers.analyzeRequest(request).getUrl());
		
		return BurpExtender.callbacks.makeHttpRequest(httpService, request);
	}
	
	public static boolean checkStringContains(String input, String match, boolean isRegex)
	{
		if(isRegex) return Pattern.compile(match).matcher(input).lookingAt();
		else return input.contains(match);
	}
	
	public static boolean checkStringEquals(String input, String match, boolean isRegex)
	{
		if(isRegex) return Pattern.matches(match, input);
		else return input.equals(match);
	}
	
	public static String getHeaderByPredicate(List<String> headers, Predicate<String> predicate)
	{
		for(String header: headers)
		{
			if(predicate.test(header))
			{
				return header;
			}
		}
		
		return null;
	}
	
	public static String getHeader(List<String> headers, String headerName)
	{
		Predicate<String> isHeader = (header) -> {return header.split(":").length == 2 && headerName.equals(getHeaderName(header));};
		return getHeaderByPredicate(headers, isHeader);
	}
	
	public static String getHeaderByRegex(List<String> headers, String headerNameRegex)
	{
		Predicate<String> isHeader = (header) -> {return header.split(":").length == 2 && Pattern.matches(headerNameRegex, getHeaderName(header));};
		return getHeaderByPredicate(headers, isHeader);
	}
	
	public static String getHeaderByString(List<String> headers, String string, boolean isRegex)
	{
		Predicate<String> isHeader;
		if(isRegex) isHeader = (header) -> {return Pattern.matches(string, header);};
		else isHeader = (header) -> {return header.equals(string);};
		
		return getHeaderByPredicate(headers, isHeader);
	}
	
	public static String getHeaderName(String header)
	{
		return header.split(":")[0];
	}
	
	public static String getHeaderValue(String header)
	{
		return header.split(":")[1];
	}
	
	public static String getHeaderValue(List<String> headers, String headerName, boolean isRegex)
	{
		String header = null;
		if(isRegex) header = getHeaderByRegex(headers, headerName);
		else header = getHeader(headers, headerName);

		if(header != null)
		{
			return getHeaderValue(header);
		}
		
		return null;
	}
	
	public static String getRequestHeaderValue(byte[] request, String headerName, boolean isRegex)
	{
		return getHeaderValue(BurpExtender.helpers.analyzeRequest(request).getHeaders(), headerName, isRegex);
	}
	
	public static String getResponseHeaderValue(byte[] response, String headerName, boolean isRegex)
	{
		return getHeaderValue(BurpExtender.helpers.analyzeResponse(response).getHeaders(), headerName, isRegex);
	}
	
	public static String getRequestFullHeader(byte[] request, String string, boolean isRegex)
	{
		return getHeaderByString(BurpExtender.helpers.analyzeRequest(request).getHeaders(), string, isRegex);
	}
	
	public static String getResponseFullHeader(byte[] response, String string, boolean isRegex)
	{
		return getHeaderByString(BurpExtender.helpers.analyzeResponse(response).getHeaders(), string, isRegex);
	}
	
	public static JsonNode getJsonNodeByFieldName(byte[] content, String fieldName)
	{
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode json;
		try
		{
			json = objectMapper.readTree(content);
			return json.findValue(fieldName);
		}
		catch(IOException e)
		{
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] updateJsonNodeValue(byte[] content, String fieldName, String newValue)
	{
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode json;
		try
		{
			json = objectMapper.readTree(content);
			JsonNode targetNode = json.findValue(fieldName);
			if(targetNode != null)
			{
				setJsonNodeValue(targetNode, fieldName, newValue);
			}
			return BurpExtender.helpers.stringToBytes(json.toString());
		}
		catch(IOException e)
		{
			e.printStackTrace();
			return content;
		}
	}
	
	public static void setJsonNodeValue(JsonNode node, String fieldName, String newValue)
	{
		((ObjectNode)node).put(fieldName, newValue);
	}
	
	public static String getJsonValue(byte[] content, String fieldName)
	{
		JsonNode json = getJsonNodeByFieldName(content, fieldName);
		if(json != null)
		{
			return json.asText();
		}
		return null;
	}
	
	public static String extractFromMessage(byte[] message, String match, boolean isRegex)
	{
		String messageString = BurpExtender.helpers.bytesToString(message);
		
		if(isRegex)
		{
			Pattern pattern = Pattern.compile(match);
			Matcher matcher = pattern.matcher(messageString);
			
			if(matcher.find())
			{
				return matcher.group();
			}
			
			return null;
		}
		
		return messageString;
	}
	
	public static Stream<IParameter> getParametersByNameRegex(byte[] request, String match, byte paramType)
	{
		return BurpExtender.helpers.analyzeRequest(request).getParameters().stream().filter((param) -> (param.getType() == paramType && Pattern.matches(match, param.getName())));
	}
	
	public static IParameter getParameterByNameRegex(byte[] request, String match, byte paramType)
	{
		return getParametersByNameRegex(request, match, paramType).findFirst().get();
	}
	
	public static IParameter getParameter(byte[] request, String paramName, byte paramType)
	{
		return BurpExtender.helpers.analyzeRequest(request).getParameters().stream().filter((param) -> (param.getType() == paramType && param.getName().equals(paramName))).findFirst().get();
	}
	
	public static String extractStringSelection(IContextMenuInvocation invocation)
	{
		int[] bounds = invocation.getSelectionBounds();
		
		if(bounds != null && ((bounds[1]-bounds[0]) > 0))
		{
			byte[] message;
			
			if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
			{
				message = invocation.getSelectedMessages()[0].getRequest();
			}
			else if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE)
			{
				message = invocation.getSelectedMessages()[0].getResponse();
			}
			else return null;
			
			byte[] selectionBytes = Arrays.copyOfRange(message, bounds[0], bounds[1]);
			
			return BurpExtender.helpers.bytesToString(selectionBytes);
		}
		
		return null;
	}
}
