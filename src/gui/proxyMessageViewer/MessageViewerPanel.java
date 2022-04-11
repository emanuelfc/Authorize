package gui.proxyMessageViewer;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JPanel;
import burp.IMessageEditor;
import gui.utils.BurpLabel;

@SuppressWarnings("serial")
public class MessageViewerPanel extends JPanel
{
	private final Insets DEFAULT_INSETS = new Insets(0, 10, 6, 0);
	
	public MessageViewerPanel(String type, IMessageEditor messageEditor)
	{
		super();

		this.setLayout(new GridBagLayout());

		GridBagConstraints gbc = new GridBagConstraints();

		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.insets = this.DEFAULT_INSETS;
		
		gbc.weightx = 1;

		BurpLabel messageLabel = new BurpLabel(type);

		gbc.gridy = 0;
		this.add(messageLabel, gbc);

		gbc.weighty = 1;
		gbc.gridy = 1;
		gbc.insets.set(0, 0, 0, 0);
		this.add(messageEditor.getComponent(), gbc);
	}
}
