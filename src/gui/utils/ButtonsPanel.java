package gui.utils;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JPanel;

@SuppressWarnings("serial")
public class ButtonsPanel  extends JPanel
{
	public ButtonsPanel(ActionListener addAction, ActionListener editAction, ActionListener removeAction)
	{
		super();
		this.setLayout(new GridBagLayout());
		this.createMainButtons(addAction, editAction, removeAction);
	}
	
	public void addButton(JButton newButton)
	{
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.FIRST_LINE_START;
		gbc.insets = new Insets(0, 0, 5, 0);
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.gridx = 0;
		gbc.gridy = this.getComponentCount();
		this.add(newButton, gbc);
	}
	
	private void createMainButtons(ActionListener addAction, ActionListener editAction, ActionListener removeAction)
	{
		JButton addButton = new JButton("Add");
		addButton.addActionListener(addAction);
		this.addButton(addButton);
		
		JButton editButton = new JButton("Edit");
		editButton.addActionListener(editAction);
		this.addButton(editButton);
		
		JButton removeButton = new JButton("Remove");
		removeButton.addActionListener(removeAction);
		this.addButton(removeButton);
	}
	
	public void addMoveButtons(ActionListener moveUpAction, ActionListener moveDownAction)
	{
		JButton moveUpButton = new JButton("Up");
		moveUpButton.addActionListener(moveUpAction);
		this.addButton(moveUpButton);
		
		JButton moveDownButton = new JButton("Down");
		moveDownButton.addActionListener(moveDownAction);
		this.addButton(moveDownButton);
	}
}
