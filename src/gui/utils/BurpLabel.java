package gui.utils;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.JLabel;
import javax.swing.UIManager;

@SuppressWarnings("serial")
public class BurpLabel extends JLabel
{
	public BurpLabel(String text)
	{
		super(text);
		
		this.setLookAndFeel();
		
		this.addPropertyChangeListener(new PropertyChangeListener()
		{
			@Override
			public void propertyChange(PropertyChangeEvent evt)
			{
				BurpLabel.this.setLookAndFeel();
			}
		});
	}
	
	private void setLookAndFeel()
	{
		// This is done elsewhere (and is recursive)
		//BurpExtender.callbacks.customizeUiComponent(this);
		
		// Only need to set the other properties to make it similar to Burp (or equal if possible)	
		this.setFont(new Font(null, Font.BOLD, 15));
		
		Color currentColor = UIManager.getColor("Label.foreground");
		
		if(currentColor.getRed() == 187 && currentColor.getGreen() == 187 && currentColor.getBlue() == 187)
		{
			this.setForeground(Color.WHITE);
		}
		else if(currentColor.getRed() == 0 && currentColor.getGreen() == 0 && currentColor.getBlue() == 0)
		{
			this.setForeground(new Color(255, 102, 51));
		}
	}
	
	public BurpLabel()
	{
		this(null);
	}
	
}
