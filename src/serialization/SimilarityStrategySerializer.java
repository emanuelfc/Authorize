package serialization;

import java.io.IOException;
import java.util.Map.Entry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import authorize.enforcement.SimilarityStrategies;
import authorize.enforcement.SimilarityStrategy;

@SuppressWarnings("serial")
public class SimilarityStrategySerializer extends StdSerializer<SimilarityStrategy>
{
	public SimilarityStrategySerializer()
	{
		this(null);
	}
	
	public SimilarityStrategySerializer(Class<SimilarityStrategy> strat)
	{
		super(strat);
	}

	@Override
	public void serialize(SimilarityStrategy value, JsonGenerator gen, SerializerProvider provider) throws IOException
	{
		if(SimilarityStrategies.strategies.containsValue(value))
		{	
			String strategyName = null;
			
			for(Entry<String, SimilarityStrategy> entry: SimilarityStrategies.strategies.entrySet())
			{
				if(entry.getValue().equals(value)) strategyName = entry.getKey();
			}
			
			gen.writeString(strategyName);
		}
	}
}