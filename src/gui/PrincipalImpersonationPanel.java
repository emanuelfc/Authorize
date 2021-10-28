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

import authorize.principal.Principal;
import burp.BurpExtender;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class PrincipalImpersonationPanel extends AbstractEntityPanel
{
	public static final String PRINCIPAL_IMPERSONATION_PANEL_NAME = "Impersonate Principal";
	
	private static final Principal dummy = new Principal("None");
	
	public PrincipalImpersonationPanel()
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		
		gbc.gridy = 0;
		gbc.gridwidth = 2;
		gbc.insets = new Insets(5, 0, 10, 0);
		
		JLabel tableLabel = new JLabel(PRINCIPAL_IMPERSONATION_PANEL_NAME);
		tableLabel.setFont(new Font(tableLabel.getFont().getName(), Font.BOLD, 15));
		tableLabel.setForeground(new Color(255, 102, 51));
		this.add(tableLabel, gbc);
		
		super.addLabeledComponent("Impersonate Principal:", this.createComboBox());
	}
	
	private Principal[] createPrincipalOptions()
	{
		Collection<Principal> optionsCollection = BurpExtender.instance.getAuthorize().getPrincipals().values();
		
		Principal[] options = new Principal[optionsCollection.size()];
		return optionsCollection.toArray(options);
	}
	
	private JComboBox<Principal> createComboBox()
	{
		JComboBox<Principal> comboBox = new JComboBox<Principal>(this.createPrincipalOptions());
		comboBox.addItem(dummy);
		comboBox.setSelectedItem(dummy);
		
		comboBox.addItemListener(new ItemListener()
		{

			@Override
			public void itemStateChanged(ItemEvent e)
			{
				if(e.getStateChange() == ItemEvent.SELECTED)
				{
					Principal selectedPrincipal = (Principal) comboBox.getSelectedItem();
					
					if(selectedPrincipal.equals(dummy))
					{
						selectedPrincipal = null;
					}
					
					BurpExtender.instance.getAuthorize().setImpersonatingPrincipal(selectedPrincipal);	
				}
			}
			
		});
		
		comboBox.addPopupMenuListener(new PopupMenuListener()
		{

			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e)
			{
				comboBox.removeAllItems();
				
				for(Principal p: PrincipalImpersonationPanel.this.createPrincipalOptions())
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
