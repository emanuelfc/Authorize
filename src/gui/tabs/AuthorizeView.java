package gui.tabs;

import java.awt.Component;

import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import burp.BurpExtender;
import burp.ITab;
import gui.menus.AuthorizeMenu;
import gui.tabs.configTab.ConfigurationTab;
import gui.tabs.proxyTab.ProxyTab;
import gui.tabs.usersTab.UsersTab;

@SuppressWarnings("serial")
public class AuthorizeView extends JTabbedPane implements ITab, ChangeListener
{
	private ProxyTab proxyTab;
	private UsersTab usersTab;
	private ConfigurationTab configurationTab;
	
	public AuthorizeView()
	{
		super();
		
		// Menu Items
		BurpExtender.callbacks.registerContextMenuFactory(new AuthorizeMenu());
		
		// Proxy Tab
		this.proxyTab = new ProxyTab();
		this.add(this.proxyTab.getName(), this.proxyTab);
		
		// Users Tab
		this.usersTab = new UsersTab();
		this.add(this.usersTab.getName(), this.usersTab);
		
		// Configuration Tab
		this.configurationTab = new ConfigurationTab();
		this.add(this.configurationTab.getName(), this.configurationTab);
	}
	
	public ProxyTab getProxyTab()
	{
		return this.proxyTab;
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
