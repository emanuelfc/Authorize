package authorize.enforcement;

import java.util.LinkedList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import authorize.matcher.MatchRule;
import authorize.types.EnforcementStatus;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class EnforcementManager
{
	private List<MatchRule> rules;
	private double authScore;
	private double unauthScore;
	private SimilarityStrategy similarityStrat;
	
	public EnforcementManager()
	{
		this.rules = new LinkedList<MatchRule>();
		this.authScore = 1.0;
		this.unauthScore = -1.0;
		this.similarityStrat = SimilarityStrategies.Equals;
	}
	
	public EnforcementManager(@JsonProperty("enforcementRules") List<MatchRule> rules, 
					   @JsonProperty("authorizedScore") double authScore,
					   @JsonProperty("unauthorizedScore") double unauthScore,
					   @JsonProperty("similarityStrategy") String similarityStrat)
	{
		this.rules = rules;
		this.authScore = authScore;
		this.unauthScore = unauthScore;
		this.similarityStrat = SimilarityStrategies.strategies.get(similarityStrat);
	}
	
	public boolean testEnforcementRules(IHttpRequestResponse principalMessageInfo)
	{
		synchronized(this.rules)
		{
			// Check Enforcement Rules, returns Unauthorized Access if any rule fails (rule returns true)
			return this.rules.stream().anyMatch((rule) -> (rule.apply(principalMessageInfo)));
		}
	}
	
	public List<MatchRule> getEnforcementRules()
	{
		return this.rules;
	}
	
	public void addRule(MatchRule newRule)
	{
		if(!this.rules.contains(newRule))
		{
			this.rules.add(newRule);
		}
	}
	
	public void removeRule(MatchRule rule)
	{
		this.rules.remove(rule);
	}
	
	public double getAuthorizedScore()
	{
		return this.authScore;
	}
	
	public void setAuthorizedScore(double authScore)
	{
		this.authScore = authScore;
	}
	
	public double getUnauthorizedScore()
	{
		return this.unauthScore;
	}
	
	public void setUnauthorizedScore(double unauthScore)
	{
		this.unauthScore = unauthScore;
	}
	
	public SimilarityStrategy getSimilarityStrategy()
	{
		return this.similarityStrat;
	}
	
	public void setStrategy(SimilarityStrategy strat)
	{
		this.similarityStrat = strat;
	}
	
	public EnforcementStatus testContentSimilarity(IHttpRequestResponse originalMessageInfo, IHttpRequestResponse principalMessageInfo)
	{
		String originalContent = BurpExtender.helpers.bytesToString(AuthorizeUtils.copyResponseBody(originalMessageInfo.getResponse()));
		String principalContent = BurpExtender.helpers.bytesToString(AuthorizeUtils.copyResponseBody(principalMessageInfo.getResponse()));
		
		if(similarityStrat.equals(SimilarityStrategies.Equals))
		{
			if(similarityStrat.test(originalContent, principalContent) == 1.0)
			{
				return EnforcementStatus.AUTHORIZED;
			}
			
			return EnforcementStatus.UNKNOWN;
		}
		else
		{
			double score = similarityStrat.test(originalContent, principalContent);
			
			if(score >= this.authScore)
			{
				return EnforcementStatus.AUTHORIZED;
			}
			else if(score < this.unauthScore)
			{
				return EnforcementStatus.UNAUTHORIZED;
			}
			else return EnforcementStatus.UNKNOWN;
		}
	}
}
