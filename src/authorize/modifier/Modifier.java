package authorize.modifier;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

@FunctionalInterface
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "className")
public interface Modifier
{
	public byte[] modify(byte[] content);
}
