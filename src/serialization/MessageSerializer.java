package serialization;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import authorize.AuthorizeUtils;
import authorize.messages.Message;
import authorize.messages.PrincipalMessage;
import authorize.messages.ProxyMessage;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class MessageSerializer
{
	public static <T extends Message> List<T> readMessageHistory(Class<T> clazz, String url) throws JsonParseException, JsonMappingException, IOException, URISyntaxException
	{
		IHttpRequestResponse[] httpMessages = BurpExtender.callbacks.getSiteMap(url);
		
		List<T> messages = new LinkedList<T>();
		
		if(httpMessages != null && httpMessages.length != 0)
		{
			ObjectMapper objectMapper = new ObjectMapper();
			
			for(IHttpRequestResponse httpMessage: httpMessages)
			{
				byte[] body = AuthorizeUtils.copyRequestBody(httpMessage.getRequest());
				
				if(body.length != 0)
				{
					T message = objectMapper.readValue(body, clazz);
					messages.add(message);
				}
			}
		}
		
		return messages;
	}
	
	public static Map<Integer, ProxyMessage> readProxyMessageHistory() throws JsonParseException, JsonMappingException, IOException, URISyntaxException
	{
		Map<Integer, ProxyMessage> messages = new HashMap<Integer, ProxyMessage>();
		
		for(ProxyMessage message: readMessageHistory(ProxyMessage.class, AuthorizeSerializer.AUTHORIZE_MESSAGES_URL))
		{
			messages.put(message.getId(), message);
		}
		
		return messages;
	}
	
	public static Map<Integer, PrincipalMessage> readPrincipalMessageHistory(String url) throws JsonParseException, JsonMappingException, IOException, URISyntaxException
	{
		IHttpRequestResponse[] httpMessages = BurpExtender.callbacks.getSiteMap(url);
		
		Map<Integer, PrincipalMessage> messages = new HashMap<Integer, PrincipalMessage>();
		
		if(httpMessages != null && httpMessages.length != 0)
		{
			ObjectMapper objectMapper = new ObjectMapper();
			
			for(IHttpRequestResponse httpMessage: httpMessages)
			{
				URL messageUrl = BurpExtender.helpers.analyzeRequest(httpMessage).getUrl();
				String[] pathSegments = messageUrl.getPath().split("/");
				String idStr = pathSegments[pathSegments.length-1];
				
				try
				{
					int id = Integer.parseInt(idStr);
					
					byte[] body = AuthorizeUtils.copyRequestBody(httpMessage.getRequest());
					
					if(body.length != 0)
					{
						PrincipalMessage message = objectMapper.readValue(body, PrincipalMessage.class);
						messages.putIfAbsent(id, message);
					}
				}
				catch(NumberFormatException  ex)
				{
					ex.printStackTrace();
				}
				
				
			}
		}
		
		return messages;
	}
}
