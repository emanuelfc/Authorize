package authorize.modifier.replace;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

import authorize.modifier.Modifier;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "className")
public interface ReplaceModifier extends Modifier
{
	public String getMatch();
	public void setMatch(String newMatch);
	public boolean isRegex();
	public void setRegex(boolean flag);
	public String getReplace();
	public void setReplace(String replace);
}
