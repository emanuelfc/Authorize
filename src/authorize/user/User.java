package authorize.user;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.messages.UserMessage;
import authorize.modifier.ModifierRule;
import authorize.sessionManagement.SessionManager;
import burp.IHttpRequestResponse;

public class User
{
	private String name;
	private SessionManager sessionManager;
	@JsonIgnore
	private ConcurrentMap<Integer, UserMessage> messages;
	private List<PrivateInfo> privateInfo;
	private List<ModifierRule> modifierRules;
	private boolean enabled;
	
	@JsonCreator
	public User(@JsonProperty("name") String name)
	{
		this.name = name;
		this.sessionManager = new SessionManager();
		this.messages = new ConcurrentHashMap<Integer, UserMessage>();
		this.privateInfo = new LinkedList<PrivateInfo>();
		this.modifierRules = new LinkedList<ModifierRule>();
		this.enabled = false;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof User)
		{
			return this.equals((User) other);
		}
		
		return false;
	}
	
	public boolean equals(User other)
	{
		return this.name.equals(other.name);
	}
	
	public String getName()
	{
		return this.name;
	}
	
	public void setName(String newName)
	{
		this.name = newName;
	}
	
	public UserMessage getMessage(int id)
	{
		return this.messages.get(id);
	}
	
	public void addMessage(int messageId, UserMessage message)
	{
		this.messages.putIfAbsent(messageId, message);
	}
	
	public void setMessages(Map<Integer, UserMessage> messages)
	{
		this.messages = new ConcurrentHashMap<Integer, UserMessage>(messages);
	}
	
	public void deleteMessage(int id)
	{
		this.messages.remove(id);
	}
	
	public ConcurrentMap<Integer, UserMessage> getMessages()
	{
		return this.messages;
	}
	
	public void deleteMessages()
	{
		this.messages = new ConcurrentHashMap<Integer, UserMessage>();
	}
	
	public void buildRequest(IHttpRequestResponse message)
	{
		byte[] baseRequest = message.getRequest();
		
		for(ModifierRule modifier: this.modifierRules)
		{
			if(modifier.isEnabled())
			{
				baseRequest = modifier.modify(baseRequest);
			}
		}
		
		message.setRequest(baseRequest);
		
		this.sessionManager.insertSession(message);
	}
	
	public SessionManager getSessionManager()
	{
		return this.sessionManager;
	}
	
	public boolean hasPrivateInfo(IHttpRequestResponse messageInfo)
	{		
		synchronized(this.privateInfo)
		{
			return this.privateInfo.stream().anyMatch((privateInfo) -> (privateInfo.hasPrivateInfo(messageInfo)));
		}
	}
	
	public List<PrivateInfo> getPrivateInfo()
	{
		synchronized(this.privateInfo)
		{
			return this.privateInfo;
		}
	}
	
	public boolean addPrivateInfo(PrivateInfo privateInfo)
	{
		synchronized(this.privateInfo)
		{
			if(!this.privateInfo.contains(privateInfo))
			{
				return this.privateInfo.add(privateInfo);
			}
			
			return false;
		}
	}
	
	public boolean removePrivateInfo(PrivateInfo privateInfo)
	{
		synchronized(this.privateInfo)
		{
			return this.privateInfo.remove(privateInfo);
		}
	}
	
	public boolean isEnabled()
	{
		return this.enabled;
	}
	
	public void setEnabled(boolean value)
	{
		this.enabled = value;
	}
	
	public void toggleEnable()
	{
		this.enabled = !this.enabled;
	}
	
	public List<ModifierRule> getModifierRules()
	{
		return this.modifierRules;
	}
	
	@Override
	public String toString()
	{
		return this.name;
	}
}
