package authorize.enforcement;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import serialization.SimilarityStrategySerializer;

@JsonSerialize(using = SimilarityStrategySerializer.class)
@FunctionalInterface
public interface SimilarityStrategy
{
	public double test(String s1, String s2);
}
