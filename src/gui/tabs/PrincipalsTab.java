package gui.tabs;

import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;

import gui.controllerPanels.PrincipalModifierRulesControllerPanel;
import gui.controllerPanels.PrincipalsControllerPanel;
import gui.controllerPanels.PrivateInfoControllerPanel;
import gui.sessionManagement.SessionManagerPanel;

@SuppressWarnings("serial")
public class PrincipalsTab extends JScrollPane
{
	public static final String PRINCIPALS_TAB_NAME = "Principals";
	
	public PrincipalsTab()
	{
		super();
		
		this.setName(PRINCIPALS_TAB_NAME);
		
		JPanel principalsPanel = new JPanel();
		this.setViewportView(principalsPanel);
		principalsPanel.setLayout(new BoxLayout(principalsPanel, BoxLayout.Y_AXIS));
		principalsPanel.setBorder(new EmptyBorder(10, 45, 10, 30));
		
		PrincipalsControllerPanel principalsControllerPanel = new PrincipalsControllerPanel();
		principalsPanel.add(principalsControllerPanel);
		
		SessionManagerPanel sessionManagerPanel = new SessionManagerPanel();
		principalsControllerPanel.addSelectEntryListener(sessionManagerPanel::onSelection);
		principalsPanel.add(sessionManagerPanel);
		
		PrivateInfoControllerPanel privateInfoControllerPanel = new PrivateInfoControllerPanel();
		principalsControllerPanel.addSelectEntryListener(privateInfoControllerPanel::onSelection);
		principalsPanel.add(privateInfoControllerPanel);
		
		PrincipalModifierRulesControllerPanel modifiersControllerPanel = new PrincipalModifierRulesControllerPanel();
		principalsControllerPanel.addSelectEntryListener(modifiersControllerPanel::onSelection);
		principalsPanel.add(modifiersControllerPanel);
	}
}
