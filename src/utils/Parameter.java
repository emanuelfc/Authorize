package utils;

import burp.IParameter;

public class Parameter implements IParameter
{
	private byte type;
	private String name;
	private String value;
	private int nameStart;
	private int nameEnd;
	private int valueStart;
	private int valueEnd;
	
	public Parameter(IParameter p)
	{
		this.type = p.getType();
		this.name = p.getName();
		this.value = p.getValue();
		this.nameStart = p.getNameStart();
		this.nameEnd = p.getNameEnd();
		this.valueStart = p.getValueStart();
		this.valueEnd = p.getValueEnd();
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof IParameter)
		{
			return this.equals((IParameter)other);
		}
		
		return false;
	}
	
	public boolean equals(IParameter other)
	{
		return (this.type == other.getType()) && (this.name.equals(other.getName()) && this.value.equals(other.getValue()));
	}
	
	@Override
	public byte getType()
	{
		return this.type;
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
	
	public void setValue(String value)
	{
		this.value = value;
	}

	@Override
	public int getNameStart()
	{
		return this.nameStart;
	}

	@Override
	public int getNameEnd()
	{
		return this.nameEnd;
	}
	
	@Override
	public int getValueStart()
	{
		return this.valueStart;
	}

	@Override
	public int getValueEnd()
	{
		return this.valueEnd;
	}
	
	@Override
	public String toString()
	{
		return this.name + "=" + this.value;
	}

}
