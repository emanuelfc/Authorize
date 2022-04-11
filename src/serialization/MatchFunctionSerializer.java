package serialization;

import java.io.IOException;
import java.util.Map.Entry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import authorize.matcher.MatchFunction;
import authorize.matcher.MatchFunctions;

@SuppressWarnings("serial")
public class MatchFunctionSerializer extends StdSerializer<MatchFunction>
{
	public MatchFunctionSerializer()
	{
		this(null);
	}
	
	public MatchFunctionSerializer(Class<MatchFunction> matchType)
	{
		super(matchType);
	}

	@Override
	public void serialize(MatchFunction value, JsonGenerator gen, SerializerProvider provider) throws IOException
	{
		if(MatchFunctions.matchFunctions.containsValue(value))
		{	
			String matchType = null;
			
			for(Entry<String, MatchFunction> entry: MatchFunctions.matchFunctions.entrySet())
			{
				if(entry.getValue().equals(value)) matchType = entry.getKey();
			}
			
			gen.writeString(matchType);
		}
	}
}