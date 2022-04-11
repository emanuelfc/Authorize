package utils;

import java.util.LinkedList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import serialization.HttpRequestResponseWithMarkersSerializer;

@JsonSerialize(using = HttpRequestResponseWithMarkersSerializer.class)
public class HttpRequestResponseWithMarkers extends HttpRequestResponse implements IHttpRequestResponseWithMarkers
{
	private List<int[]> requestMarkers;
	private List<int[]> responseMarkers;
	
	@JsonCreator
	public HttpRequestResponseWithMarkers(@JsonProperty("request") byte[] request,
										  @JsonProperty("response") byte[] response,
										  @JsonProperty("httpService") @JsonDeserialize(as = HttpService.class) IHttpService httpService,
										  @JsonProperty("comment") String comment,
										  @JsonProperty("highlightColor") String highlightColor,
										  @JsonProperty("requestMarkers") List<int[]> requestMarkers,
										  @JsonProperty("responseMarkers") List<int[]> responseMarkers)
	{
		super(request, response, httpService, comment, highlightColor);
		this.requestMarkers = requestMarkers;
		this.responseMarkers = responseMarkers;
	}
	
	@JsonCreator
	public HttpRequestResponseWithMarkers(@JsonProperty("request") byte[] request,
										  @JsonProperty("response") byte[] response,
										  @JsonProperty("httpService") @JsonDeserialize(as = HttpService.class) IHttpService httpService,
										  @JsonProperty("comment") String comment,
										  @JsonProperty("highlightColor") String highlightColor)
	{
		this(request, response, httpService, comment, highlightColor, new LinkedList<int[]>(), new LinkedList<int[]>());
	}

	@Override
	public List<int[]> getRequestMarkers() 
	{
		return this.requestMarkers;
	}

	@Override
	public List<int[]> getResponseMarkers()
	{
		return this.responseMarkers;
	}

	
}
