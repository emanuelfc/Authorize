package gui.tabs.usersTab;

import java.awt.Dimension;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;

import authorize.sessionManagement.CookiesSessionHandler;
import burp.BurpExtender;
import burp.ITextEditor;

@SuppressWarnings("serial")
public class CookieSessionHandlerPanel extends JPanel
{
	private ITextEditor cookiesTextEditor;
	
	public CookieSessionHandlerPanel(String cookies)
	{
		super();
		this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		this.setAlignmentX(LEFT_ALIGNMENT);
		
		this.cookiesTextEditor = BurpExtender.callbacks.createTextEditor();
		this.cookiesTextEditor.setText(BurpExtender.helpers.stringToBytes(cookies));
		
		JLabel cookiesLabel = new JLabel("Cookies");
		cookiesLabel.setAlignmentX(LEFT_ALIGNMENT);
		this.add(cookiesLabel);
		
		this.add(cookiesTextEditor.getComponent());
		
		cookiesTextEditor.getComponent().setPreferredSize(new Dimension(500, 500));
	}
	
	public CookieSessionHandlerPanel(CookiesSessionHandler cookieSessionHandler)
	{
		this(cookieSessionHandler.getSession());
	}
	
	public String getCookies()
	{
		return BurpExtender.helpers.bytesToString(this.cookiesTextEditor.getText());
	}
}
