package utils;

import java.util.Date;

import burp.ICookie;

public class Cookie implements ICookie
{
	private String domain;
	private String path;
	private Date expirationDate;
	private String name;
	private String value;
	
	public Cookie(String domain, String path, Date expirationDate, String name, String value)
	{
		this.domain = domain;
		this.path = path;
		this.expirationDate = expirationDate;
		this.name = name;
		this.value = value;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof ICookie)
		{
			return this.equals((ICookie)other);
		}
		
		return false;
	}
	
	public boolean equals(ICookie other)
	{
		return this == other || (this.domain.equals(other.getDomain()) 
				&& this.path.equals(other.getPath()) 
				&& this.expirationDate.equals(other.getExpiration()) 
				&& this.name.equals(other.getName()) 
				&& this.value.equals(other.getValue()));
	}

	@Override
	public String getDomain()
	{
		return this.domain;
	}

	@Override
	public String getPath()
	{
		return this.path;
	}

	@Override
	public Date getExpiration()
	{
		return this.expirationDate;
	}
	
	@Override
	public String getName()
	{
		return this.name;
	}

	@Override
	public String getValue()
	{
		return this.value;
	}
	
	@Override
	public String toString()
	{
		return this.name + "=" + this.value + ";";
	}

}
