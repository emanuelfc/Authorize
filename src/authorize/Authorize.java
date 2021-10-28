package authorize;

import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.enforcement.EnforcementManager;
import authorize.interception.InterceptionManager;
import authorize.matcher.MatchRule;
import authorize.matcher.MatchRuleFactory;
import authorize.messages.Message;
import authorize.messages.PrincipalMessage;
import authorize.messages.ProxyMessage;
import authorize.messages.TestMessage;
import authorize.modifier.Modifier;
import authorize.modifier.ModifierRule;
import authorize.modifier.remove.RemoveHeaderModifier;
import authorize.principal.Principal;
import authorize.types.EnforcementStatus;
import authorize.types.MatchType;
import authorize.types.ModifierType;
import authorize.types.RelationshipType;
import authorize.types.ToolType;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;

public class Authorize
{
	@JsonIgnore
	private ConcurrentSkipListMap<Integer, ProxyMessage> proxyMessages;
	private ConcurrentMap<String, Principal> principals;
	
	private InterceptionManager interceptionManager;
	private EnforcementManager enforcementManager;
	private List<ModifierRule> globalModifierRules;
	
	private AtomicInteger curIndex;
	private AtomicBoolean enabled;
	
	@JsonIgnore
	private Principal impersonatingPrincipal;
	
	public Authorize()
	{
		this.proxyMessages = new ConcurrentSkipListMap<Integer, ProxyMessage>();
		this.curIndex = new AtomicInteger(0);
		this.principals = new ConcurrentHashMap<String, Principal>();
		this.interceptionManager = new InterceptionManager();
		this.enforcementManager = new EnforcementManager();
		this.globalModifierRules = new LinkedList<ModifierRule>();
		this.enabled = new AtomicBoolean(false);
		this.impersonatingPrincipal = null;
		
		this.initDefault();
	}
	
	@JsonCreator
	public Authorize(@JsonProperty("principals") Map<String, Principal> principals,
					 @JsonProperty("interceptionManager") InterceptionManager interceptionManager,
					 @JsonProperty("enforcementManager") EnforcementManager enforcementManager,
					 @JsonProperty("globalModifiers") List<ModifierRule> globalModifierRules,
					 @JsonProperty("enabled") boolean enabled)
	{
		this.proxyMessages = new ConcurrentSkipListMap<Integer, ProxyMessage>();
		this.curIndex = new AtomicInteger(0);
		this.principals = new ConcurrentHashMap<String, Principal>(principals);
		this.interceptionManager = interceptionManager;
		this.enforcementManager = enforcementManager;
		this.globalModifierRules = new LinkedList<ModifierRule>(globalModifierRules);
		this.enabled = new AtomicBoolean(enabled);
		this.impersonatingPrincipal = null;
	}
	
	private void initDefault()
	{
		this.addPrincipal(new Principal("Anonymous"));
		
		Principal noAuth = new Principal("No Auth");

		Modifier removeCookies = new RemoveHeaderModifier("Cookie:.*", true);
		ModifierRule removeCookiesRule = new ModifierRule(removeCookies, ModifierType.REMOVE_HEADER, true, "Removes Cookies");
		
		Modifier removeAuthHeader = new RemoveHeaderModifier("Authorization:.*", true);
		ModifierRule removeAuthHeaderRule = new ModifierRule(removeAuthHeader, ModifierType.REMOVE_HEADER, true, "Removes Authorization Header");
		
		noAuth.getModifierRules().add(removeCookiesRule);
		noAuth.getModifierRules().add(removeAuthHeaderRule);
		
		noAuth.setEnabled(true);
		this.addPrincipal(noAuth);
		
		
		this.interceptionManager.getToolInterceptionRule().addTool(ToolType.PROXY.getToolFlag());
		
		
		MatchRule unauthorized = MatchRuleFactory.createMatchRule(MatchType.STATUS_CODE, "401", RelationshipType.MATCH.getRelationship(), "401 - Unauthorized", true);
		enforcementManager.addRule(unauthorized);
		
		MatchRule forbidden = MatchRuleFactory.createMatchRule(MatchType.STATUS_CODE, "403", RelationshipType.MATCH.getRelationship(), "403 - Forbidden", true);
		enforcementManager.addRule(forbidden);
		
		MatchRule methodNotAllowed = MatchRuleFactory.createMatchRule(MatchType.STATUS_CODE, "405", RelationshipType.MATCH.getRelationship(), "405 - Method Not Allowed", true);
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
	
	private boolean hasEnabledPrincipals()
	{
		Predicate<Principal> enabledPrincipalPredicate = (principal) -> (principal.isEnabled());
		return this.principals.values().stream().anyMatch(enabledPrincipalPredicate);
	}
	
	public boolean processMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if(!this.interceptionManager.testInterception(toolFlag, messageInfo)) return false;
		
		boolean processed = false;
		
		if(messageIsRequest)
		{
			if(this.impersonatingPrincipal != null)
			{
				messageInfo.setRequest(this.impersonatingPrincipal.makeRequest(messageInfo.getRequest()));
			}
		}
		else
		{
			if(this.enabled.get())
			{
				// No need to process message if no principals are enabled
				if(this.hasEnabledPrincipals());
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
		
		byte[] baseRequest = this.applyGlobalModifiers(messageInfo.getRequest());
		
		boolean actingSessionProcessed = false;
		
		for(Principal principal: this.principals.values())
		{
			synchronized(principal)
			{
				PrincipalMessage principalMessage = null;
				
				if(principal.isEnabled())
				{
					if(!actingSessionProcessed && principal.getSessionManager().isSession(messageInfo.getRequest()))
					{
						principalMessage = new PrincipalMessage(messageInfo, EnforcementStatus.ACTING_USER);
						actingSessionProcessed = true;
					}
					else principalMessage = this.testPrincipalAuthorization(principal, baseRequest, messageInfo);
				}
				else principalMessage = new PrincipalMessage(null, EnforcementStatus.DISABLED);
				
				principal.addMessage(index, principalMessage);
			}
		}
	}
	
	private void processSessions(IHttpRequestResponse messageInfo)
	{
		for(Principal principal: this.principals.values())
		{
			synchronized(principal)
			{
				if(principal.getSessionManager().isSession(messageInfo.getRequest()))
				{
					if(messageInfo.getResponse() != null)
					{
						principal.getSessionManager().updateSession(messageInfo);
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
			
			byte[] baseRequest = this.applyGlobalModifiers(messageInfo.getRequest());
			
			for(Principal principal: this.principals.values())
			{
				synchronized(principal)
				{
					PrincipalMessage principalMessage = principal.getMessage(messageId);
					if(principalMessage != null && principalMessage.getMessage() != null && !principalMessage.getStatus().equals(EnforcementStatus.ACTING_USER))
					{
						principal.addMessage(index, this.testPrincipalAuthorization(principal, baseRequest, messageInfo));
					}
				}
			}
		}
	}
	
	public void retestAuthorizationForPrincipal(int messageId, Principal principal)
	{
		IHttpRequestResponse messageInfo = this.proxyMessages.get(messageId).getMessage();
		if(messageInfo != null)
		{
			synchronized(principal)
			{
				PrincipalMessage principalMessage = principal.getMessage(messageId);
				if(principalMessage != null && principalMessage.getMessage() != null && !principalMessage.getStatus().equals(EnforcementStatus.ACTING_USER))
				{
					byte[] baseRequest = this.applyGlobalModifiers(messageInfo.getRequest());
					
					principal.addMessage(this.curIndex.getAndIncrement(), this.testPrincipalAuthorization(principal, baseRequest, messageInfo));
				}
			}
		}
	}
	
	private PrincipalMessage testPrincipalAuthorization(Principal principal, byte[] baseRequest, IHttpRequestResponse originalMessageInfo)
	{
		IHttpRequestResponse messageInfo = this.sendAsPrincipal(principal, baseRequest, originalMessageInfo.getHttpService());
		
		EnforcementStatus enforcementStatus = this.testEnforcementStatus(originalMessageInfo, messageInfo, principal);
		
		PrincipalMessage message = new PrincipalMessage(messageInfo, enforcementStatus);
		
		return message;
	}
	
	public IHttpRequestResponse sendAsPrincipal(Principal principal, byte[] baseRequest, IHttpService httpService)
	{
		synchronized(principal)
		{
			byte[] request = principal.makeRequest(baseRequest);
			
			IHttpRequestResponse messageInfo = BurpExtender.callbacks.makeHttpRequest(httpService, request);
			
			// Update principal session
			principal.getSessionManager().updateSession(messageInfo);
			
			return messageInfo;
		}
	}
	
	private boolean hasPrivateInfo(IHttpRequestResponse messageInfo, Principal principal)
	{
		Predicate<Principal> hasPrincipalPrivateInfo = (otherPrincipal) -> (otherPrincipal.equals(principal) ? false : otherPrincipal.hasPrivateInfo(messageInfo));
		
		return this.principals.values().stream().anyMatch(hasPrincipalPrivateInfo);
	}
	
	private EnforcementStatus testEnforcementStatus(IHttpRequestResponse originalMessageInfo, IHttpRequestResponse principalMessageInfo, Principal principal)
	{
		if(this.enforcementManager.testEnforcementRules(principalMessageInfo)) return EnforcementStatus.UNAUTHORIZED;
		
		// Check if response contains Private Information of any Principal
		if(this.hasPrivateInfo(principalMessageInfo, principal))
		{
			return EnforcementStatus.AUTHORIZED;
		}
		
		return this.enforcementManager.testContentSimilarity(originalMessageInfo, principalMessageInfo);
	}
	
	private void testEnforcement(Message message, Principal principal, PrincipalMessage principalMessage)
	{
		EnforcementStatus newStatus = this.testEnforcementStatus(message.getMessage(), principalMessage.getMessage(), principal);
		principalMessage.setStatus(newStatus);
	}
	
	private void retestEnforcement(ProxyMessage message, Principal principal)
	{
		synchronized(principal)
		{
			PrincipalMessage principalMessage = principal.getMessage(message.getId());
			if(principalMessage != null && principalMessage.getMessage() != null)
			{
				this.testEnforcement(message, principal, principalMessage);
			}
		}
	}
	
	public void retestEnforcement(int messageId, Principal principal)
	{
		ProxyMessage originalMessage = this.proxyMessages.get(messageId);
		if(originalMessage != null)
		{
			this.retestEnforcement(originalMessage, principal);
		}
	}
	
	public void retestEnforcementAll(int messageId)
	{
		ProxyMessage originalMessage = this.proxyMessages.get(messageId);
		if(originalMessage != null)
		{
			for(Principal principal: this.principals.values())
			{
				this.retestEnforcement(originalMessage, principal);
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
		this.curIndex = new AtomicInteger(this.proxyMessages.lastKey());
	}
	
	public void deleteMessage(int id)
	{
		this.proxyMessages.remove(id);
		
		for(Principal principal: this.principals.values())
		{
			principal.deleteMessage(id);
		}
	}
	
	public ConcurrentMap<String, Principal> getPrincipals()
	{
		return this.principals;
	}
	
	public void addPrincipal(String name)
	{
		this.addPrincipal(new Principal(name));
	}
	
	public void addPrincipal(Principal principal)
	{
		this.principals.putIfAbsent(principal.getName(), principal);
	}
	
	public void removePrincipal(String name)
	{
		Principal removedPrincipal = this.principals.remove(name);
		
		if(removedPrincipal != null)
		{
			if(this.impersonatingPrincipal.equals(removedPrincipal)) this.impersonatingPrincipal = null;
		}
	}
	
	@JsonIgnore
	public Principal getImpersonatingPrincipal()
	{
		return this.impersonatingPrincipal;
	}
	
	public void setImpersonatingPrincipal(Principal newImpersonatingPrincipal)
	{
		this.impersonatingPrincipal = newImpersonatingPrincipal;
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

	
	
	
	
	
	
	
	private List<TestMessage> testMessages = new LinkedList<TestMessage>();
	
	@JsonIgnore
	public List<TestMessage> getTests()
	{
		return this.testMessages;
	}
	
	public void setTests(List<TestMessage> testMessages)
	{
		this.testMessages = new LinkedList<TestMessage>(testMessages);
	}
	
	public void deleteTestMessage(int testIndex)
	{
		this.testMessages.remove(testIndex);
	}
	
	public void executeTest(int testIndex)
	{
		TestMessage testMessage = this.testMessages.get(testIndex);
		
		IHttpRequestResponse testMessageInfo = testMessage.getMessage();
		
		if(testMessageInfo != null)
		{
			for(Principal principal: this.principals.values())
			{
				synchronized(principal)
				{
					testMessage.insertPrincipalTest(principal.getName(), testPrincipalAuthorization(principal, testMessageInfo.getRequest(), testMessageInfo));
				}
			}
		}
		
		testMessage.setTimestamp(new Date());
	}
	
	public void executeTest(TestMessage testMessage)
	{
		IHttpRequestResponse testMessageInfo = testMessage.getMessage();
		
		if(testMessageInfo != null)
		{
			for(Principal principal: this.principals.values())
			{
				synchronized(principal)
				{
					testMessage.insertPrincipalTest(principal.getName(), testPrincipalAuthorization(principal, testMessageInfo.getRequest(), testMessageInfo));
				}
			}
		}
		
		testMessage.setTimestamp(new Date());
	}
	
	public void executeTestForPrincipal(int testIndex, Principal principal)
	{
		TestMessage testMessage = this.testMessages.get(testIndex);
		
		IHttpRequestResponse testMessageInfo = testMessage.getMessage();
		
		if(testMessageInfo != null)
		{			
			synchronized(principal)
			{
				testMessage.insertPrincipalTest(principal.getName(), testPrincipalAuthorization(principal, testMessageInfo.getRequest(), testMessageInfo));
			}
		}
	}
	
	public void executeTestForPrincipal(TestMessage testMessage, Principal principal)
	{
		IHttpRequestResponse testMessageInfo = testMessage.getMessage();
		
		if(testMessageInfo != null)
		{			
			synchronized(principal)
			{
				testMessage.insertPrincipalTest(principal.getName(), testPrincipalAuthorization(principal, testMessageInfo.getRequest(), testMessageInfo));
			}
		}
	}
	
	public void executeEnforcementTest(int testIndex)
	{
		TestMessage testMessage = this.testMessages.get(testIndex);
		
		for(Entry<String, PrincipalMessage> entry: testMessage.getPrincipalMessages().entrySet())
		{
			this.testEnforcement(testMessage, this.principals.get(entry.getKey()), entry.getValue());
			testMessage.setTimestamp(new Date());
		}
	}
	
	public void executeEnforcementTest(TestMessage testMessage)
	{
		for(Entry<String, PrincipalMessage> entry: testMessage.getPrincipalMessages().entrySet())
		{
			this.testEnforcement(testMessage, this.principals.get(entry.getKey()), entry.getValue());
			testMessage.setTimestamp(new Date());
		}
	}
	
	public void executeEnforcementTestForPrincipal(int testIndex, Principal principal)
	{
		TestMessage testMessage = this.testMessages.get(testIndex);
		PrincipalMessage principalMessage = testMessage.getPrincipalMessage(principal.getName());
		this.testEnforcement(testMessage, principal, principalMessage);
	}
	
	public void executeEnforcementTestForPrincipal(TestMessage testMessage, Principal principal)
	{
		PrincipalMessage principalMessage = testMessage.getPrincipalMessage(principal.getName());
		this.testEnforcement(testMessage, principal, principalMessage);
	}
}
