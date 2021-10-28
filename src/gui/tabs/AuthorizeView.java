package gui.tabs;

import java.awt.Component;

import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import burp.BurpExtender;
import burp.ITab;
import gui.menus.AuthorizeMenu;

@SuppressWarnings("serial")
public class AuthorizeView extends JTabbedPane implements ITab, ChangeListener
{
	private ProxyTab proxyTab;
	private PrincipalsTab principalsTab;
	private TestsTab testsTab;
	private ConfigurationTab configurationTab;
	
	public AuthorizeView()
	{
		super();
		
		// Menu Items
		BurpExtender.callbacks.registerContextMenuFactory(new AuthorizeMenu());
		
		// Proxy Tab
		this.proxyTab = new ProxyTab();
		this.add(this.proxyTab.getName(), this.proxyTab);
		
		// Principals Tab
		this.principalsTab = new PrincipalsTab();
		this.add(this.principalsTab.getName(), this.principalsTab);
		
		// Tests Tab
		this.testsTab = new TestsTab();
		this.add(this.testsTab, this.testsTab.getName());
		
		// Configuration Tab
		this.configurationTab = new ConfigurationTab();
		this.add(this.configurationTab.getName(), this.configurationTab);
	}
	
	public ProxyTab getProxyTab()
	{
		return this.proxyTab;
	}
	
	public TestsTab getTestsTab()
	{
		return this.testsTab;
	}
	
	@Override
	public String getTabCaption()
	{
		return BurpExtender.EXTENSION_NAME;
	}
	
	@Override
	public Component getUiComponent()
	{
		return this;
	}

	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.proxyTab.stateChanged(e);
		this.configurationTab.stateChanged(e);
	}
}
