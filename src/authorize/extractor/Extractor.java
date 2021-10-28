package authorize.extractor;

public interface Extractor
{	
	public String extract(byte[] content, String match, boolean isRegex);
}
