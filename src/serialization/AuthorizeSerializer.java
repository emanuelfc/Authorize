package serialization;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.web.util.UriUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import authorize.Authorize;
import authorize.AuthorizeUtils;
import authorize.messages.Message;
import authorize.messages.UserMessage;
import authorize.messages.ProxyMessage;
import authorize.user.User;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import utils.HttpRequestResponse;
import utils.HttpService;

public class AuthorizeSerializer
{
	public static final String AUTHORIZE_HOSTNAME = "authorize.local";
	
	public static final String AUTHORIZE_URL = "https://" + AUTHORIZE_HOSTNAME;
	
	// Example: https://authorize.local/settings
	public static final String AUTHORIZE_PROJECT_SETTINGS_URL = AUTHORIZE_URL + "/settings";
	
	public static final String AUTHORIZE_MESSAGES_URL = AUTHORIZE_URL + "/messages/";
	
	public static final String AUTHORIZE_MESSAGE_URL = AUTHORIZE_MESSAGES_URL + "%d";
	
	// Example: https://authorize.local/admin/
	public static final String AUTHORIZE_USER_URL = AUTHORIZE_URL + "/%s";
	
	public static final String AUTHORIZE_USER_MESSAGES_URL = AUTHORIZE_USER_URL + "/messages/";
	
	// Example: https://authorize.local/admin/messages/1
	public static final String AUTHORIZE_USER_MESSAGE_URL = AUTHORIZE_USER_MESSAGES_URL + "%d";
	
	public static ObjectMapper createSerializer()
	{
		ObjectMapper objectMapper = new ObjectMapper();

		return objectMapper;
	}
	
	/*
	 * WRITE
	 */
	
	public static void save()
	{
		Authorize authorize = BurpExtender.instance.getAuthorize();
		
		ObjectMapper objectMapper = createSerializer();
		
		saveAuthorizeSettings(authorize, objectMapper);
		
		try
		{
			saveMessageHistory(authorize.getMessages().values(), AUTHORIZE_MESSAGE_URL, objectMapper);
			for(User user: authorize.getUserManager().getUsers().values())
			{
				String userMessageURL = String.format(AUTHORIZE_USER_MESSAGES_URL, UriUtils.encodePath(user.getName(), StandardCharsets.UTF_8));
				saveUserMessageHistory(user.getMessages().entrySet(), userMessageURL, objectMapper);
			}
			
			System.out.println("Successfully saved Authorize messages.");
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.out.println("Failed to save Authorize messages.");
		}
		
	}
	
	private static void saveAuthorizeSettings(Authorize authorize, ObjectMapper objectMapper)
	{
		try
		{
			writeToBurpSiteMap(AUTHORIZE_PROJECT_SETTINGS_URL, serializeAuthorize(objectMapper));
			
			System.out.println("Successfully saved Authorize Settings.");
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.out.println("Failed to save Authorize Settings.");
		}		
	}
	
	public static String serializeAuthorize(ObjectMapper objectMapper)
	{
		String authorizeSettings = null;
		
		try
		{
			authorizeSettings = objectMapper.writeValueAsString(BurpExtender.instance.getAuthorize());
			System.out.println("Successfully serialized Authorize Settings.");
		}
		catch(Exception e)
		{
			e.printStackTrace();
			System.out.println("Failed to serialize Authorize Settings.");
		}
		
		return authorizeSettings;
	}
	
	private static void writeToBurpSiteMap(String url, String requestContent) throws MalformedURLException
	{		
		String request = "GET " + (new URL(url)).getPath() + " HTTP/1.0\r\n\r\n";
		request += requestContent;
		String response = "HTTP/1.1 200 OK\r\n\r\n";
		IHttpRequestResponse httpMessage = new HttpRequestResponse(request.getBytes(), response.getBytes(), HttpService.buildFromURL(url));
		BurpExtender.callbacks.addToSiteMap(httpMessage);
	}
	
	public static void saveMessage(Message message, String url, ObjectMapper objectMapper) throws JsonProcessingException, MalformedURLException
	{
		writeToBurpSiteMap(url, objectMapper.writeValueAsString(message));
	}
	
	private static void saveMessageHistory(Collection<ProxyMessage> messages, String baseURL, ObjectMapper objectMapper) throws JsonProcessingException, MalformedURLException
	{
		for(ProxyMessage message: messages)
		{
			String url = String.format(baseURL, message.getId());
			saveMessage(message, url, objectMapper);
		}
	}
	
	private static void saveUserMessageHistory(Collection<Entry<Integer,UserMessage>> entries, String baseURL, ObjectMapper objectMapper) throws JsonProcessingException, MalformedURLException
	{
		for(Entry<Integer, UserMessage> entry: entries)
		{
			String url = baseURL + entry.getKey();
			saveMessage(entry.getValue(), url, objectMapper);
		}
	}
	
	private static void removeMessage(String baseURL, int messageId) throws MalformedURLException
	{
		String url = String.format(baseURL, messageId);
		writeToBurpSiteMap(url, "");
	}
	
	public static void removeHistoryMessage(int messageId) throws MalformedURLException
	{
		removeMessage(AUTHORIZE_MESSAGE_URL, messageId);
		
		for(User user: BurpExtender.instance.getAuthorize().getUserManager().getUsers().values())
		{
			removeUserMessage(messageId, user);
		}
	}
	
	public static void removeUserMessage(int messageId, User user) throws MalformedURLException
	{
		String userMessageURL = String.format(AUTHORIZE_USER_MESSAGES_URL, user.getName()) + "%d";
		removeMessage(userMessageURL, messageId);
	}
	
	/*
	 * READ
	 */
	
	public static Authorize load()
	{
		Authorize authorize = null;
		try
		{
			authorize = readAuthorizeSettings();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		
		if(authorize != null)
		{
			try
			{
				Map<Integer, ProxyMessage> messages = MessageSerializer.readProxyMessageHistory();
				if(!messages.isEmpty())
				{
					authorize.setMessages(messages);
					for(User user: authorize.getUserManager().getUsers().values())
					{
						String userURL = String.format(AUTHORIZE_USER_MESSAGES_URL, UriUtils.encodePath(user.getName(), StandardCharsets.UTF_8));
						Map<Integer, UserMessage> userMessages = MessageSerializer.readUserMessageHistory(userURL);
						user.setMessages(userMessages);
					}
					
					System.out.println("Successfully loaded Authorize messages.");
				}
				else System.out.println("No Messages to load.");
			}
			catch(Exception e)
			{
				System.out.println("Failed to load Authorize messages.");
				e.printStackTrace();
			}
		}
		
		return authorize;
	}
	
	public static Authorize readAuthorizeSettings() throws JsonMappingException, JsonProcessingException
	{
		Authorize authorize = null;
		
		IHttpRequestResponse[] httpSettingsMessages = BurpExtender.callbacks.getSiteMap(AUTHORIZE_PROJECT_SETTINGS_URL);
		
		if(httpSettingsMessages != null && httpSettingsMessages.length != 0)
		{
			IHttpRequestResponse httpSettingsMessage = httpSettingsMessages[0];
			String authorizeProjectSettings = BurpExtender.helpers.bytesToString(AuthorizeUtils.copyRequestBody(httpSettingsMessage.getRequest()));

			ObjectMapper objectMapper = new ObjectMapper();
			authorize = objectMapper.readValue(authorizeProjectSettings, Authorize.class);
			
			System.out.println("Successfully loaded Authorize Project Settings.");
		}
		else System.out.println("No Authorize Project Settings found in the current Burp Project.");
		
		return authorize;
	}
}
