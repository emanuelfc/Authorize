package utils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import serialization.HttpRequestResponseSerializer;
import utils.httpMessage.HttpMessage;
import utils.httpMessage.HttpRequest;

@JsonSerialize(using = HttpRequestResponseSerializer.class)
public class HttpRequestResponse implements IHttpRequestResponse
{
	private IHttpService httpService;
	private byte[] request, response;
	private String comment;
	private String highlightColor;
	
	@JsonCreator
	public HttpRequestResponse(@JsonProperty("request") byte[] request, @JsonProperty("response") byte[] response, @JsonProperty("httpService") @JsonDeserialize(as = HttpService.class) IHttpService httpService, @JsonProperty("comment") String comment, @JsonProperty("highlightColor") String highlightColor)
	{
		this.request = request;
		this.response = response;
		this.httpService = httpService;
		this.comment = comment;
		this.highlightColor = highlightColor;
	}
	
	public HttpRequestResponse(byte[] request, byte[] response, IHttpService httpService)
	{
		this(request, response, httpService, new String(), new String());
	}
	
	public static HttpRequestResponse copy(IHttpRequestResponse messageInfo)
	{
		HttpMessage httpMessage = new HttpMessage(messageInfo);
		return new HttpRequestResponse(httpMessage.getRequest().copyRequest(), httpMessage.getResponse().copyResponse(), messageInfo.getHttpService(), messageInfo.getComment(), messageInfo.getHighlight());
	}
	
	public static HttpRequestResponse copyRequest(IHttpRequestResponse messageInfo)
	{
		HttpRequest httpRequest = new HttpRequest(messageInfo);
		return new HttpRequestResponse(httpRequest.copyRequest(), null, messageInfo.getHttpService(), messageInfo.getComment(), messageInfo.getHighlight());
	}

	@Override
	public byte[] getRequest()
	{
		return this.request;
	}

	@Override
	public void setRequest(byte[] message)
	{
		this.request = message;
	}

	@Override
	public byte[] getResponse()
	{
		return this.response;
	}

	@Override
	public void setResponse(byte[] message)
	{
		this.response = message;
	}

	@Override
	public String getComment()
	{
		return this.comment;
	}

	@Override
	public void setComment(String comment)
	{
		this.comment = comment;
	}

	@Override
	public String getHighlight()
	{
		return this.highlightColor;
	}

	@Override
	public void setHighlight(String color)
	{
		this.highlightColor = color;
	}

	@Override
	public IHttpService getHttpService()
	{
		return this.httpService;
	}

	@Override
	public void setHttpService(IHttpService httpService)
	{
		this.httpService = httpService;
	}
	
	@Override
	public String toString()
	{
		return BurpExtender.helpers.analyzeRequest(this.request).getUrl().toString();
	}
}
