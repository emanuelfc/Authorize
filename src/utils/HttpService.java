package utils;

import java.net.MalformedURLException;
import java.net.URL;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import burp.IHttpService;

public class HttpService implements IHttpService
{
	private String host;
	private int port;
	private String protocol;
	
	@JsonCreator
	public HttpService(@JsonProperty("host") String host, @JsonProperty("port") int port, @JsonProperty("protocol") String protocol)
	{
		this.host = host;
		this.port = port;
		this.protocol = protocol;
	}
	
	public static final HttpService buildFromURL(URL url) throws MalformedURLException
	{
		int port = url.getPort();
		if(url.getProtocol().equals("https")) port = 443;
		else if(url.getProtocol().equals("http")) port = 80;
		else port = 443;
		return new HttpService(url.getHost(), port, url.getProtocol());
	}
	
	public static final HttpService buildFromURL(String url_String) throws MalformedURLException
	{
		return buildFromURL(new URL(url_String));
	}
	
	@Override
	public String getHost()
	{
		return this.host;
	}

	@Override
	public int getPort()
	{
		return this.port;
	}
	
	@Override
	public String getProtocol()
	{
		return this.protocol;
	}
	
	@Override
	public String toString()
	{
		return this.protocol + "://" + this.host + ":" + this.port;
	}
}