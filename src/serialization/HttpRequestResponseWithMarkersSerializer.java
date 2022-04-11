package serialization;

import java.io.IOException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import burp.IHttpRequestResponseWithMarkers;

/*
 * Somehow when serializing IHttpRequestResponse it adds additional variables, port, protocol, etc,
 * which i wasnt able to remove through simple annotations.
 * 
 * Making this simple fix for now. Make it simpler later.
 */
public class HttpRequestResponseWithMarkersSerializer extends StdSerializer<IHttpRequestResponseWithMarkers>
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public HttpRequestResponseWithMarkersSerializer(Class<IHttpRequestResponseWithMarkers> httpRequestResponseWithMarkers)
	{
		super(httpRequestResponseWithMarkers);
	}
	
	public HttpRequestResponseWithMarkersSerializer()
	{
		this(null);
	}

	@Override
	public void serialize(IHttpRequestResponseWithMarkers httpRequestResponseWithMarkers, JsonGenerator gen, SerializerProvider provider) throws IOException
	{
		gen.writeStartObject();
		
		gen.writeBinaryField("request", httpRequestResponseWithMarkers.getRequest());
		gen.writeBinaryField("response", httpRequestResponseWithMarkers.getResponse());
		gen.writeStringField("comment", httpRequestResponseWithMarkers.getComment());
		gen.writeStringField("highlight", httpRequestResponseWithMarkers.getHighlight());
		gen.writeObjectField("httpService", httpRequestResponseWithMarkers.getHttpService());
		gen.writeObjectField("requestMarkers", httpRequestResponseWithMarkers.getRequestMarkers());
		gen.writeObjectField("responseMarkers", httpRequestResponseWithMarkers.getResponseMarkers());
		
		gen.writeEndObject();
	}
	
}