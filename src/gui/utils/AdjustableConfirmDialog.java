package gui.utils;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;

import javax.swing.JDialog;
import javax.swing.JOptionPane;

public class AdjustableConfirmDialog
{
	@SuppressWarnings("deprecation")
	public static int showAdjustableConfirmDialog(Component parentComponent, Container message, String title, int optionType, int messageType)
	{
		JOptionPane pane = new JOptionPane(message, messageType, optionType, null, null, null);
		
		JDialog dialog = pane.createDialog(parentComponent, title);
		
		message.addContainerListener(new ContainerListener()
		{

			@Override
			public void componentAdded(ContainerEvent e)
			{
				dialog.pack();
			}

			@Override
			public void componentRemoved(ContainerEvent e)
			{
				dialog.pack();
			}	
		});
		
		dialog.show();
		dialog.dispose();

		Object selectedValue = pane.getValue();

		if(selectedValue == null) return JOptionPane.CLOSED_OPTION;
		
		if(selectedValue instanceof Integer) return ((Integer)selectedValue).intValue();
		return JOptionPane.CLOSED_OPTION;
	}
}
