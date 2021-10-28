package authorize.enforcement;

import java.util.Map;

import org.apache.commons.text.similarity.CosineDistance;
import org.apache.commons.text.similarity.HammingDistance;
import org.apache.commons.text.similarity.JaccardDistance;
import org.apache.commons.text.similarity.JaroWinklerDistance;
import org.apache.commons.text.similarity.LevenshteinDistance;

public class SimilarityStrategies
{
	public static final SimilarityStrategy Equals = new SimilarityStrategy()
	{

		@Override
		public double test(String s1, String s2)
		{
			boolean equals = s1.equals(s2);
			
			if(equals) return 1.0;
			else return 0.0;
		}

	};
	public static final SimilarityStrategy CosineDistance = (new CosineDistance())::apply;
	public static final SimilarityStrategy HammingDistance = (new HammingDistance())::apply;
	public static final SimilarityStrategy JaccardDistance = (new JaccardDistance())::apply;
	public static final SimilarityStrategy JaroWinklerDistance = (new JaroWinklerDistance())::apply;
	public static final SimilarityStrategy LevenshteinDistance = (new LevenshteinDistance())::apply;
	
	public static final Map<String, SimilarityStrategy> strategies = Map.of(
		"Equals", Equals,
		"CosineDistance", CosineDistance,
		"HammingDistance", HammingDistance,
		"JaccardDistance", JaccardDistance,
		"JaroWinklerDistance", JaroWinklerDistance,
		"LevenshteinDistance", LevenshteinDistance
	);
}
