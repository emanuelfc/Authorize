package authorize.enforcement;

import java.util.LinkedList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.interception.MatchRule;
import authorize.types.EnforcementStatus;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import utils.httpMessage.HttpResponse;

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
		this.unauthScore = 0.0;
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
	
	public boolean testEnforcementRules(IHttpRequestResponse userMessage)
	{
		synchronized(this.rules)
		{
			// Check Enforcement Rules, returns Unauthorized Access if any rule fails (rule returns true)
			return this.rules.stream().anyMatch((rule) -> (rule.apply(userMessage)));
		}
	}
	
	public List<MatchRule> getEnforcementRules()
	{
		return this.rules;
	}
	
	public boolean addRule(MatchRule newRule)
	{
		if(!this.rules.contains(newRule))
		{
			return this.rules.add(newRule);
		}
		
		return false;
	}
	
	public boolean removeRule(MatchRule rule)
	{
		return this.rules.remove(rule);
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
	
	public EnforcementStatus testContentSimilarity(HttpResponse originalResponse, HttpResponse userResponse)
	{
		double authScore = this.authScore;
		
		if(similarityStrat.equals(SimilarityStrategies.Equals))
		{		
			authScore = 1.0;
		}
		
		String originalContent = BurpExtender.helpers.bytesToString(originalResponse.toBytes());
		String userContent = BurpExtender.helpers.bytesToString(userResponse.toBytes());
		
		double score = similarityStrat.test(originalContent, userContent);
		
		//System.out.println("Content Similarity Algorithm = " + similarityStrat.getClass());
		//System.out.println("authScore = " + authScore + "; unauthScore = " + this.unauthScore + "; score = " + score);
		
		if(score >= authScore)
		{
			//System.out.println("ContentSimilarity Result = Authorized");
			
			if(score == 1.0)
			{
				//System.out.println("Equal Content");
				return EnforcementStatus.AUTHORIZED_EQUAL_CONTENT;
			}
			else
			{
				//System.out.println("Similar Content");
				return EnforcementStatus.AUTHORIZED_SIMILAR_CONTENT;
			}
		}
		else if(score <= this.unauthScore)
		{
			//System.out.println("ContentSimilarity Result = Unauthorized");
			return EnforcementStatus.UNAUTHORIZED_NOT_ACCEPTABLE_SIMILAR_CONTENT;
		}
		else
		{
			//System.out.println("ContentSimilarity Result = Unknown");
			return EnforcementStatus.UNKNOWN;
		}
	}
}
