package gui.tabs.usersTab;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import section.Section;

@SuppressWarnings("serial")
public class UsersTab extends JScrollPane
{
	public UsersTab()
	{
		super();
		
		this.setName("Users");
		
		JPanel usersPanel = new JPanel();
		this.setViewportView(usersPanel);
		usersPanel.setLayout(new BoxLayout(usersPanel, BoxLayout.Y_AXIS));
		usersPanel.setBorder(new EmptyBorder(15, 45, 10, 30));
		
		Section usersSection = new Section("Users");
		UsersController usersController = new UsersController(); 
		usersSection.addSectionComponent(usersController);
		usersPanel.add(usersSection);
		
		usersPanel.add(Box.createVerticalStrut(24));
		usersPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
		usersPanel.add(Box.createVerticalStrut(19));
		
		Section sessionHandlersSection = new Section("Session Handlers");
		SessionManagerPanel sessionManagerPanel = new SessionManagerPanel();
		sessionHandlersSection.addSectionComponent(sessionManagerPanel);
		usersController.addSelectionListener(sessionManagerPanel::onSelection);
		usersPanel.add(sessionHandlersSection);
		
		usersPanel.add(Box.createVerticalStrut(24));
		usersPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
		usersPanel.add(Box.createVerticalStrut(19));
		
		Section privateInfoSection = new Section("Private Info", "Specify confidential information exclusive to the selected user.\n"
				+ "This will help identifying Access Control vulnerabilities as Authorize will analyse a User's HTTP Response for Private Information of other Users.");
		PrivateInfoControllerPanel privateInfoControllerPanel = new PrivateInfoControllerPanel();
		privateInfoSection.addSectionComponent(privateInfoControllerPanel);
		usersController.addSelectionListener(privateInfoControllerPanel::onSelection);
		usersPanel.add(privateInfoSection);
		
		usersPanel.add(Box.createVerticalStrut(24));
		usersPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
		usersPanel.add(Box.createVerticalStrut(19));
		
		Section userModifiersSection = new Section("User Modifiers");
		UserModifierRulesControllerPanel modifiersControllerPanel = new UserModifierRulesControllerPanel();
		usersController.addSelectionListener(modifiersControllerPanel::onSelection);
		userModifiersSection.addSectionComponent(modifiersControllerPanel);
		usersPanel.add(userModifiersSection);	
	}
}
