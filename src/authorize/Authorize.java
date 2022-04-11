package authorize;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.enforcement.EnforcementManager;
import authorize.interception.InterceptionManager;
import authorize.interception.MatchRule;
import authorize.interception.InterceptionRuleFactory;
import authorize.messages.Message;
import authorize.messages.UserMessage;
import authorize.messages.ProxyMessage;
import authorize.modifier.ModifierRule;
import authorize.types.EnforcementStatus;
import authorize.types.MatchType;
import authorize.types.RelationshipType;
import authorize.types.ToolType;
import authorize.user.PrivateInfo;
import authorize.user.User;
import authorize.user.UsersManager;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import utils.HttpRequestResponse;
import utils.httpMessage.HttpMessage;
import utils.httpMessage.HttpResponse;

public class Authorize
{
	@JsonIgnore
	private ConcurrentSkipListMap<Integer, ProxyMessage> proxyMessages;
	
	@JsonIgnore
	private UsersManager users;
	
	private InterceptionManager interceptionManager;
	private EnforcementManager enforcementManager;
	private List<ModifierRule> globalModifierRules;
	
	private AtomicInteger curIndex;
	private AtomicBoolean enabled;
	
	public Authorize()
	{
		this.proxyMessages = new ConcurrentSkipListMap<Integer, ProxyMessage>();
		
		this.curIndex = new AtomicInteger(0);
		this.enabled = new AtomicBoolean(false);
		
		this.users = new UsersManager();
		
		this.interceptionManager = new InterceptionManager();
		this.enforcementManager = new EnforcementManager();
		this.globalModifierRules = new LinkedList<ModifierRule>();
		
		this.initDefault();
	}
	
	@JsonCreator
	public Authorize(@JsonProperty("users") Map<String, User> users,
					 @JsonProperty("interceptionManager") InterceptionManager interceptionManager,
					 @JsonProperty("enforcementManager") EnforcementManager enforcementManager,
					 @JsonProperty("globalModifiers") List<ModifierRule> globalModifierRules,
					 @JsonProperty("enabled") boolean enabled)
	{
		this.proxyMessages = new ConcurrentSkipListMap<Integer, ProxyMessage>();
		
		this.curIndex = new AtomicInteger(0);
		this.enabled = new AtomicBoolean(enabled);
		
		if(users != null) this.users = new UsersManager(users);
		else this.users = new UsersManager();
		
		this.interceptionManager = interceptionManager;
		this.enforcementManager = enforcementManager;
		this.globalModifierRules = new LinkedList<ModifierRule>(globalModifierRules);
	}
	
	private void initDefault()
	{
		this.interceptionManager.getToolInterceptionRule().addTool(ToolType.PROXY.getToolFlag());
		
		MatchRule inScope = InterceptionRuleFactory.createMatchRule(MatchType.SCOPE, "", RelationshipType.MATCH.getRelationship(), false, "Burp Suite Target Scope", true);
		this.interceptionManager.getInterceptionRules().add(inScope);
		
		MatchRule unauthorized = InterceptionRuleFactory.createMatchRule(MatchType.STATUS_CODE, "401", RelationshipType.MATCH.getRelationship(), false, "401 - Unauthorized", true);
		enforcementManager.addRule(unauthorized);
		
		MatchRule forbidden = InterceptionRuleFactory.createMatchRule(MatchType.STATUS_CODE, "403", RelationshipType.MATCH.getRelationship(), false, "403 - Forbidden", true);
		enforcementManager.addRule(forbidden);
		
		MatchRule methodNotAllowed = InterceptionRuleFactory.createMatchRule(MatchType.STATUS_CODE, "405", RelationshipType.MATCH.getRelationship(), false, "405 - Method Not Allowed", true);
		enforcementManager.addRule(methodNotAllowed);
	}
	
	public boolean isEnabled()
	{
		return this.enabled.get();
	}

	public void setEnabled(boolean newValue)
	{
		this.enabled.set(newValue);
	}

	public void toggleEnable()
	{
		this.enabled.set(!this.enabled.get());
	}
	
	@JsonIgnore
	public UsersManager getUserManager()
	{
		return this.users;
	}
	
	public ConcurrentMap<String, User> getUsers()
	{
		return this.users.getUsers();
	}
	
	public boolean processMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if(!this.interceptionManager.testInterception(toolFlag, messageInfo)) return false;
		
		boolean processed = false;
		
		if(messageIsRequest)
		{
			User impersonatingUser = this.users.getImpersonatingUser();
			
			if(impersonatingUser != null)
			{
				impersonatingUser.buildRequest(messageInfo);
			}
		}
		else
		{
			if(this.enabled.get())
			{
				// No need to process message if no users are enabled
				if(this.users.hasEnabledUsers());
				{
					this.processAuthorization(messageInfo);
					
					processed = true;
				}
			}
		}
		
		this.processSessions(messageInfo);

		return processed;
	}
	
	private byte[] applyGlobalModifiers(byte[] message)
	{
		byte[] baseRequest = Arrays.copyOf(message, message.length);
		synchronized(this.globalModifierRules)
		{
			for(ModifierRule modifier: this.globalModifierRules)
			{
				synchronized(modifier)
				{
					if(modifier.isEnabled())
					{
						baseRequest = modifier.modify(baseRequest);
					}
				}
			}
		}
		
		return baseRequest;
	}
	
	private void processAuthorization(IHttpRequestResponse messageInfo)
	{
		int index = this.curIndex.getAndIncrement();
		
		this.proxyMessages.putIfAbsent(index, new ProxyMessage(index, messageInfo));
		
		IHttpRequestResponse baseRequest = HttpRequestResponse.copyRequest(messageInfo);
		baseRequest.setRequest(this.applyGlobalModifiers(messageInfo.getRequest()));
		
		boolean actingSessionProcessed = false;
		
		for(User user: this.users.getOrderedEnabledUsers())
		{
			synchronized(user)
			{
				UserMessage userMessage = null;
				
				if(!actingSessionProcessed && user.getSessionManager().isSession(messageInfo))
				{
					userMessage = new UserMessage(messageInfo, EnforcementStatus.ACTING_USER);
					actingSessionProcessed = true;
				}
				else
				{
					userMessage = this.testUserAuthorization(user, baseRequest, messageInfo);
				}
				
				user.addMessage(index, userMessage);
			}
		}
	}
	
	private void processSessions(IHttpRequestResponse messageInfo)
	{
		for(User user: this.users.getOrderedEnabledUsers())
		{
			synchronized(user)
			{
				if(user.getSessionManager().isSession(messageInfo))
				{
					if(messageInfo.getResponse() != null)
					{
						user.getSessionManager().updateSession(messageInfo);
					}
				}
			}
		}
	}
	
	public void retestAuthorization(int messageId)
	{
		IHttpRequestResponse messageInfo = this.proxyMessages.get(messageId).getMessage();
		
		if(messageInfo != null)
		{
			int index = this.curIndex.getAndIncrement();
			
			this.proxyMessages.putIfAbsent(index, new ProxyMessage(index, messageInfo));
			
			IHttpRequestResponse baseRequest = HttpRequestResponse.copyRequest(messageInfo);
			
			baseRequest.setRequest(this.applyGlobalModifiers(messageInfo.getRequest()));
			
			for(User user: this.users.getOrderedEnabledUsers())
			{
				synchronized(user)
				{
					UserMessage userMessage = user.getMessage(messageId);
					if(userMessage != null && userMessage.getMessage() != null && !userMessage.getStatus().equals(EnforcementStatus.ACTING_USER))
					{
						UserMessage newUserMessage = this.testUserAuthorization(user, baseRequest, messageInfo);
						user.addMessage(index, newUserMessage);
					}
				}
			}
		}
	}
	
	public void retestAuthorizationForUser(int messageId, User user)
	{
		IHttpRequestResponse messageInfo = this.proxyMessages.get(messageId).getMessage();
		if(messageInfo != null)
		{
			synchronized(user)
			{
				UserMessage userMessage = user.getMessage(messageId);
				if(userMessage != null && userMessage.getMessage() != null && !userMessage.getStatus().equals(EnforcementStatus.ACTING_USER))
				{
					HttpRequestResponse baseHttpMessage = HttpRequestResponse.copyRequest(messageInfo);
					baseHttpMessage.setRequest(this.applyGlobalModifiers(baseHttpMessage.getRequest()));
					user.addMessage(this.curIndex.getAndIncrement(), this.testUserAuthorization(user, baseHttpMessage, messageInfo));
				}
			}
		}
	}
	
	private UserMessage testUserAuthorization(User user, IHttpRequestResponse baseMessageInfo, IHttpRequestResponse originalMessageInfo)
	{
		IHttpRequestResponse userMessageInfo = this.sendAsUser(user, baseMessageInfo);
		
		EnforcementStatus enforcementStatus = this.testEnforcementStatus(originalMessageInfo, userMessageInfo, user);
		
		UserMessage message = new UserMessage(userMessageInfo, enforcementStatus);
		
		return message;
	}
	
	public IHttpRequestResponse sendAsUser(User user, IHttpRequestResponse messageInfo)
	{
		synchronized(user)
		{
			IHttpRequestResponse userRequest = HttpRequestResponse.copyRequest(messageInfo);
			user.buildRequest(userRequest);
			
			IHttpRequestResponse userHttpMessage = BurpExtender.callbacks.makeHttpRequest(userRequest.getHttpService(), userRequest.getRequest());
			
			// Update user session
			user.getSessionManager().updateSession(userHttpMessage);
			
			return userHttpMessage;
		}
	}
	
	private boolean hasPrivateInfo(IHttpRequestResponse messageInfo, User user)
	{
		Predicate<User> hasUserPrivateInfo = (otherUser) -> (otherUser.equals(user) ? false : otherUser.hasPrivateInfo(messageInfo));
		
		return this.users.getOrderedUsers().stream().anyMatch(hasUserPrivateInfo);
	}
	
	private List<int[]> getMarkersFromRegex(String content, String regex)
	{
		Matcher matcher = Pattern.compile(regex).matcher(content);
		
		List<int[]> markers = new LinkedList<int[]>();
		
		while(matcher.find())
		{
			markers.add(new int[] {matcher.start(), matcher.end()});
		}
		
		return markers;
	}
	
	private List<int[]> getMarkersFromLiteral(String content, String literal)
	{
		List<int[]> markers = new LinkedList<int[]>();
		
		// https://stackoverflow.com/a/44838176
		int count = content.split(literal, -1).length - 1;
		
		for(int i = 0; i <= count; i++)
		{
			int start = content.indexOf(literal, i);
			int end = start + literal.length();
			
			markers.add(new int[] {start, end});
		}
		
		return markers;
	}
	
	private IHttpRequestResponseWithMarkers getResponseWithPrivateInfoMarkers(IHttpRequestResponse messageInfo, User user)
	{
		List<int[]> responseMarkers = new LinkedList<int[]>();
		
		String responseString = BurpExtender.helpers.bytesToString(messageInfo.getResponse());
		
		this.users.getOrderedUsers().stream().forEach((otherUser) -> {
			
			if(!otherUser.equals(user))
			{
				for(PrivateInfo privateInfo: otherUser.getPrivateInfo())
				{
					List<int[]> markers = null;
					
					if(privateInfo.isRegex())
					{					
						markers = this.getMarkersFromRegex(responseString, privateInfo.getInfo());
					}
					else
					{
						markers = this.getMarkersFromLiteral(responseString, privateInfo.getInfo());
					}
					
					responseMarkers.addAll(markers);
				}
			}
			
		});
		
		return BurpExtender.callbacks.applyMarkers(messageInfo, null, responseMarkers);
	}
	
	private EnforcementStatus testEnforcementStatus(IHttpRequestResponse originalMessageInfo, IHttpRequestResponse userMessageInfo, User user)
	{
		if(this.enforcementManager.testEnforcementRules(userMessageInfo))
		{
			return EnforcementStatus.UNAUTHORIZED_BY_ENFORCEMENT_RULE;
		}
		
		// Check if response contains Private Information of any User
		if(this.hasPrivateInfo(userMessageInfo, user))
		{
			//System.out.println("Contains Private Info of Other Users");
			return EnforcementStatus.AUTHORIZED_CONTAINS_PRIVATE_INFO;
		}
		
		HttpMessage userMessage = new HttpMessage(userMessageInfo);
		HttpResponse originalResponse = new HttpResponse(originalMessageInfo);
		
		return this.enforcementManager.testContentSimilarity(originalResponse, userMessage.getResponse());
	}
	
	private void testEnforcement(Message message, User user, UserMessage userMessage)
	{
		EnforcementStatus newStatus = this.testEnforcementStatus(message.getMessage(), userMessage.getMessage(), user);
		userMessage.setStatus(newStatus);
	}
	
	private void retestEnforcement(ProxyMessage message, User user)
	{
		synchronized(user)
		{
			UserMessage userMessage = user.getMessage(message.getId());
			if(userMessage != null && userMessage.getMessage() != null)
			{
				this.testEnforcement(message, user, userMessage);
			}
		}
	}
	
	public void retestEnforcement(int messageId, User user)
	{
		ProxyMessage originalMessage = this.proxyMessages.get(messageId);
		if(originalMessage != null)
		{
			this.retestEnforcement(originalMessage, user);
		}
	}
	
	public void retestEnforcementAll(int messageId)
	{
		ProxyMessage originalMessage = this.proxyMessages.get(messageId);
		if(originalMessage != null)
		{
			for(User user: this.users.getOrderedUsers())
			{
				this.retestEnforcement(originalMessage, user);
			}
		}
	}
	
	@JsonIgnore
	public ConcurrentSkipListMap<Integer, ProxyMessage> getMessages()
	{
		return this.proxyMessages;
	}
	
	public void setMessages(Map<Integer, ProxyMessage> proxyMessages)
	{
		this.proxyMessages = new ConcurrentSkipListMap<Integer, ProxyMessage>(proxyMessages);
		this.curIndex = new AtomicInteger(this.proxyMessages.lastKey() + 1);
	}
	
	public void deleteMessage(int id)
	{
		this.proxyMessages.remove(id);
		
		for(User user: this.users.getUsers().values())
		{
			user.deleteMessage(id);
		}
	}
	
	public List<ModifierRule> getGlobalModifiers()
	{
		return this.globalModifierRules;
	}
	
	public InterceptionManager getInterceptionManager()
	{
		return this.interceptionManager;
	}
	
	public EnforcementManager getEnforcementManager()
	{
		return this.enforcementManager;
	}
}
