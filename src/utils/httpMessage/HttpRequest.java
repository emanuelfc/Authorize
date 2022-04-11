package utils.httpMessage;

import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import authorize.AuthorizeUtils;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

public class HttpRequest
{
	Predicate<IParameter> cookiePredicate = (param) -> (param.getType() == IParameter.PARAM_COOKIE);
	
	private IHttpRequestResponse messageInfo;
	private IRequestInfo requestInfo;
	
	public HttpRequest(IHttpRequestResponse messageInfo)
	{
		this.messageInfo = messageInfo;
		this.requestInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
	}
	
	public IHttpRequestResponse getMessageInfo()
	{
		return this.messageInfo;
	}
	
	public IRequestInfo getRequestInfo()
	{
		return this.requestInfo;
	}
	
	private void setRequest(byte[] message)
	{
		IRequestInfo newRequestInfo = BurpExtender.helpers.analyzeRequest(message);
		
		byte[] requestMessage = this.messageInfo.getRequest();
		
		byte[] newBody = Arrays.copyOfRange(requestMessage, newRequestInfo.getBodyOffset(), requestMessage.length);
		
		this.updateRequest(newRequestInfo.getHeaders(), newBody);
	}
	
	private void updateRequest(List<String> headers, byte[] body)
	{
		byte[] newRequestMessage = BurpExtender.helpers.buildHttpMessage(headers, body);
		
		this.messageInfo.setRequest(newRequestMessage);
		this.requestInfo = BurpExtender.helpers.analyzeRequest(this.messageInfo);
	}
	
	public byte[] copyRequest()
	{
		byte[] requestMessage = this.messageInfo.getRequest();
		return Arrays.copyOf(requestMessage, requestMessage.length);
	}
	
	public int getBodySize()
	{
		return this.messageInfo.getRequest().length - this.requestInfo.getBodyOffset();
	}
	
	public String getMethod()
	{
		return this.requestInfo.getMethod();
	}
	
	public URL getURL()
	{
		return this.requestInfo.getUrl();
	}
	
	public String getStartline()
	{
		return null;
	}
	
	public String getHttpVersion()
	{
		return null;
	}
	
	public byte[] copyBody()
	{
		byte[] requestMessage = this.messageInfo.getRequest();
		return Arrays.copyOfRange(requestMessage, this.requestInfo.getBodyOffset(), requestMessage.length);
	}
	
	public List<IParameter> getCookiesList()
	{
		return this.requestInfo.getParameters().stream().filter(cookiePredicate).collect(Collectors.toList());
	}
	
	public Map<String, String> getCookiesMap()
	{
		Map<String, String> cookies = new HashMap<String, String>();
		
		for(IParameter cookieParam: this.getCookiesList())
		{
			cookies.put(cookieParam.getName(), cookieParam.getValue());
		}
		
		return cookies;
	}
	
	public void addCookie(String cookieName, String cookieValue)
	{
		this.addParam(cookieName, cookieValue, IParameter.PARAM_COOKIE);
	}
	
	public void removeCookie(String cookieName, String cookieValue)
	{
		this.removeParam(cookieName, cookieValue, IParameter.PARAM_COOKIE);
	}
	
	public List<String> getHeadersList()
	{
		return this.requestInfo.getHeaders();
	}
	
	public Map<String, HttpHeader> getHeadersMap()
	{
		Map<String, HttpHeader> headers = new HashMap<String, HttpHeader>();
		
		for(String headerString: this.requestInfo.getHeaders())
		{
			HttpHeader httpHeader = HttpHeader.parseHeaderFromString(headerString);
			
			if(httpHeader != null)
			{
				headers.put(httpHeader.getName(), httpHeader);
			}
		}
		
		return headers;
	}
	
	public void addHeader(String header)
	{
		List<String> headers = this.requestInfo.getHeaders();
		
		headers.add(header);
		
		this.updateRequest(headers, this.copyBody());
	}
	
	public void putHeader(String header)
	{
		List<String> headers = this.requestInfo.getHeaders();
		
		headers = headers.stream().filter((s) -> (!AuthorizeUtils.getHeaderName(s).equals(AuthorizeUtils.getHeaderName(header)))).collect(Collectors.toList());
		
		headers.add(header);
		
		this.updateRequest(headers, this.copyBody());
	}
	
	public void putHeader(String headerName, String headerValue)
	{
		List<String> headers = this.requestInfo.getHeaders();
		
		headers = headers.stream().filter((s) -> (!AuthorizeUtils.getHeaderName(s).equals(AuthorizeUtils.getHeaderName(headerName)))).collect(Collectors.toList());
		
		String header = headerName + ": " + headerValue;
		
		headers.add(header);
		
		this.updateRequest(headers, this.copyBody());
	}
	
	public void putHeader(HttpHeader header)
	{
		List<String> headers = this.requestInfo.getHeaders();
		
		headers = headers.stream().filter((s) -> (!AuthorizeUtils.getHeaderName(s).equals(AuthorizeUtils.getHeaderName(header.getName())))).collect(Collectors.toList());
		
		String headerStr = header.getName() + ": " + header.getValue();
		
		headers.add(headerStr);
		
		this.updateRequest(headers, this.copyBody());
	}
	
	public void removeHeader(Predicate<String> predicate)
	{
		List<String> remainingHeaders = this.requestInfo.getHeaders().stream().filter(predicate).collect(Collectors.toList());
		
		this.updateRequest(remainingHeaders, this.copyBody());
	}
	
	public void updateMessage(String match, String replace, boolean isRegex)
	{
		byte[] newRequest = this.copyRequest();
		
		IRequestInfo newRequestInfo = BurpExtender.helpers.analyzeRequest(newRequest);
		
		byte[] newBody = Arrays.copyOfRange(newRequest, newRequestInfo.getBodyOffset(), newRequest.length);
		
		List<String> newHeaders = newRequestInfo.getHeaders();
		
		this.updateRequest(newHeaders, newBody);
	}
	
	public void updateBody(byte[] request, String match, boolean isRegex, String replace)
	{
		byte[] newBody = AuthorizeUtils.replaceBytes(this.copyBody(), match, isRegex, replace);
		
		this.updateRequest(this.requestInfo.getHeaders(), newBody);
	}
	
	public void addParam(IParameter param)
	{
		byte[] newRequest = this.copyRequest();

		newRequest = BurpExtender.helpers.addParameter(newRequest, param);
		
		this.setRequest(newRequest);
	}
	
	public void addParam(String name, String value, byte paramType)
	{
		IParameter newParam = BurpExtender.helpers.buildParameter(name, value, paramType);
		
		this.addParam(newParam);
	}
	
	public void updateParam(IParameter param)
	{
		IParameter oldParam = BurpExtender.helpers.getRequestParameter(this.messageInfo.getRequest(), param.getName());
		
		if(oldParam != null)
		{
			if(oldParam.getName().equals(param.getName()) && oldParam.getValue().equals(param.getValue()) && oldParam.getType() == param.getType())
			{
				byte[] newMessage = BurpExtender.helpers.updateParameter(this.messageInfo.getRequest(), param);
				
				this.setRequest(newMessage);
			}
		}
	}
	
	public void removeParam(IParameter param)
	{
		byte[] newMessage = BurpExtender.helpers.removeParameter(this.copyRequest(), param);
		
		this.setRequest(newMessage);
	}
	
	public void removeParam(String name, String value, byte paramType)
	{
		IParameter param = BurpExtender.helpers.buildParameter(name, value, paramType);
		
		this.removeParam(param);
	}
	
	public void removeParam(Predicate<IParameter> predicate)
	{
		byte[] newMessage = this.messageInfo.getRequest();
		
		for(IParameter param: this.requestInfo.getParameters())
		{
			if(predicate.test(param))
			{
				newMessage = BurpExtender.helpers.removeParameter(newMessage, param);
			}
		}
		
		this.setRequest(newMessage);
	}
	
	public HttpHeader getHeader(String headerName)
	{		
		Predicate<HttpHeader> isHeader = (header) -> header.getName().equals(headerName);
		return this.getHeader(isHeader);
	}
	
	public HttpHeader getHeader(Predicate<HttpHeader> predicate)
	{
		for(String headerString: this.requestInfo.getHeaders())
		{
			HttpHeader httpHeader = HttpHeader.parseHeaderFromString(headerString);
			
			if(httpHeader != null)
			{
				if(predicate.test(httpHeader))
				{
					return httpHeader;
				}
			}

		}
		
		return null;
	}
	
	public List<HttpHeader> getHeaders(Predicate<HttpHeader> predicate)
	{
		LinkedList<HttpHeader> headersList = new LinkedList<HttpHeader>();
		
		for(String headerString: this.requestInfo.getHeaders())
		{
			HttpHeader httpHeader = HttpHeader.parseHeaderFromString(headerString);
			
			if(httpHeader != null)
			{
				if(predicate.test(httpHeader))
				{
					headersList.add(httpHeader);
				}
			}
		}
		
		return headersList;
	}
	
	public HttpHeader getHeaderByString(Predicate<String> predicate)
	{
		for(String headerString: this.requestInfo.getHeaders())
		{
			if(predicate.test(headerString))
			{
				return HttpHeader.parseHeaderFromString(headerString);
			}
		}
		
		return null;
	}
	
	public String getHeaderStringByString(Predicate<String> predicate)
	{
		for(String headerString: this.requestInfo.getHeaders())
		{
			if(predicate.test(headerString))
			{
				return headerString;
			}
		}		
		
		return null;
	}
	
	public byte[] toBytes()
	{
		return this.messageInfo.getRequest();
	}
	
	@Override
	public String toString()
	{
		return BurpExtender.helpers.bytesToString(this.messageInfo.getRequest());
	}

}
