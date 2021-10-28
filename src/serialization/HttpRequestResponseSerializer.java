package serialization;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import burp.IHttpRequestResponse;

/*
 * Somehow when serializing IHttpRequestResponse it adds additional variables, port, protocol, etc,
 * which i wasnt able to remove through simple annotations.
 * 
 * Making this simple fix for now. Make it simpler later.
 */
public class HttpRequestResponseSerializer extends StdSerializer<IHttpRequestResponse>
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public HttpRequestResponseSerializer(Class<IHttpRequestResponse> httpRequestResponse)
	{
		super(httpRequestResponse);
	}
	
	public HttpRequestResponseSerializer()
	{
		this(null);
	}

	@Override
	public void serialize(IHttpRequestResponse httpRequestResponse, JsonGenerator gen, SerializerProvider provider) throws IOException
	{
		gen.writeStartObject();
		
		gen.writeBinaryField("request", httpRequestResponse.getRequest());
		gen.writeBinaryField("response", httpRequestResponse.getResponse());
		gen.writeStringField("comment", httpRequestResponse.getComment());
		gen.writeStringField("highlight", httpRequestResponse.getHighlight());
		gen.writeObjectField("httpService", httpRequestResponse.getHttpService());
		
		gen.writeEndObject();
	}
	
}