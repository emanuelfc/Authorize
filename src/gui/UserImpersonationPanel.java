package gui;

import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Collection;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

import authorize.user.User;
import burp.BurpExtender;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class UserImpersonationPanel extends AbstractEntityPanel
{
	public static final String USER_IMPERSONATION_PANEL_NAME = "Impersonate User";
	
	private static final User dummy = new User("None");
	
	public UserImpersonationPanel()
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		
		gbc.gridy = 0;
		gbc.gridwidth = 2;
		gbc.insets = new Insets(5, 0, 10, 0);
		
		JLabel tableLabel = new JLabel(USER_IMPERSONATION_PANEL_NAME);
		tableLabel.setFont(new Font(tableLabel.getFont().getName(), Font.BOLD, 15));
		tableLabel.setForeground(new Color(255, 102, 51));
		this.add(tableLabel, gbc);
		
		super.addLabeledComponent("Impersonate User:", this.createComboBox());
	}
	
	private User[] createUserOptions()
	{
		Collection<User> optionsCollection = BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers();
		
		User[] options = new User[optionsCollection.size()];
		return optionsCollection.toArray(options);
	}
	
	private JComboBox<User> createComboBox()
	{
		JComboBox<User> comboBox = new JComboBox<User>(this.createUserOptions());
		comboBox.addItem(dummy);
		comboBox.setSelectedItem(dummy);
		
		comboBox.addItemListener(new ItemListener()
		{

			@Override
			public void itemStateChanged(ItemEvent e)
			{
				if(e.getStateChange() == ItemEvent.SELECTED)
				{
					User selectedUser = (User) comboBox.getSelectedItem();
					
					if(selectedUser.equals(dummy))
					{
						selectedUser = null;
					}
					
					BurpExtender.instance.getAuthorize().getUserManager().setImpersonatingUser(selectedUser);	
				}
			}
			
		});
		
		comboBox.addPopupMenuListener(new PopupMenuListener()
		{

			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e)
			{
				comboBox.removeAllItems();
				
				for(User p: UserImpersonationPanel.this.createUserOptions())
				{
					comboBox.addItem(p);
				}
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e)
			{
				// TODO Auto-generated method stub
				
			}

			@Override
			public void popupMenuCanceled(PopupMenuEvent e)
			{
				// TODO Auto-generated method stub
				
			}
			
		});
		
		return comboBox;
	}

	public void refreshComboBox()
	{
		// TODO Auto-generated method stub
		
	}
}
