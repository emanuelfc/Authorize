package authorize.sessionManagement;

import authorize.extractor.Extractor;
import authorize.types.ExtractorType;

public class ResponseSessionExtractor
{
	private String match;
	private boolean isRegex;
	private Extractor extractorOperation;
	private ExtractorType extractorType;
	
	public ResponseSessionExtractor(String match, boolean isRegex, Extractor extractorOperation, ExtractorType extractorType)
	{
		this.match = match;
		this.isRegex = isRegex;
		this.extractorOperation = extractorOperation;
		this.extractorType = extractorType;
	}
	
	public String getMatch()
	{
		return this.match;
	}
	
	public void setMatch(String newMatch)
	{
		this.match = newMatch;
	}
	
	public boolean isRegex()
	{
		return this.isRegex;
	}
	
	public void setRegex(boolean isRegex)
	{
		this.isRegex = isRegex;
	}
	
	public void setExtractor(Extractor newExtractorOperation, ExtractorType extractorType)
	{
		this.extractorOperation = newExtractorOperation;
		this.extractorType = extractorType;
	}
	
	public String extractSession(byte[] response)
	{
		return this.extractorOperation.extract(response, this.match, this.isRegex);
	}
	
	public ExtractorType getExtractorType()
	{
		return this.extractorType;
	}
	
}
