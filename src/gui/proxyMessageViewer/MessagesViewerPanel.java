package gui.proxyMessageViewer;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import burp.IMessageEditor;

@SuppressWarnings("serial")
public class MessagesViewerPanel extends JPanel
{
	private MessageViewerPanel requestViewer;
	private MessageViewerPanel responseViewer;
	
	private Component messageViewerLayout;
	
	public MessagesViewerPanel(IMessageEditor requestEditor, IMessageEditor responseEditor)
	{
		super();

		this.setLayout(new GridBagLayout());
		
		this.requestViewer = new MessageViewerPanel("Request", requestEditor);
		this.responseViewer = new MessageViewerPanel("Response", responseEditor);

		GridBagConstraints gbc = new GridBagConstraints();

		gbc.anchor = GridBagConstraints.EAST;
		gbc.fill = GridBagConstraints.NONE;
		
		// Buttons and Layouts
		JPanel layoutSelectionButtons = new JPanel();
		
		JButton horizontalSplit = new JButton("|");
		horizontalSplit.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				MessagesViewerPanel.this.changeLayout(new HorizontalLayout(MessagesViewerPanel.this.requestViewer, MessagesViewerPanel.this.responseViewer));
			}
	
		});
		layoutSelectionButtons.add(horizontalSplit);
		
		JButton verticalSplit = new JButton("-");
		verticalSplit.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				MessagesViewerPanel.this.changeLayout(new VerticalLayout(MessagesViewerPanel.this.requestViewer, MessagesViewerPanel.this.responseViewer));
			}
	
		});
		layoutSelectionButtons.add(verticalSplit);
		
		JButton tabbedSplit = new JButton("T");
		tabbedSplit.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				MessagesViewerPanel.this.changeLayout(new TabLayout(MessagesViewerPanel.this.requestViewer, MessagesViewerPanel.this.responseViewer));
			}
	
		});
		layoutSelectionButtons.add(tabbedSplit);

		gbc.gridy = 0;
		this.add(layoutSelectionButtons, gbc);
		
		// Default Option
		this.messageViewerLayout = new HorizontalLayout(this.requestViewer, this.responseViewer);
		
		this.changeLayout(this.messageViewerLayout);
	}
	
	private void changeLayout(Component newLayout)
	{
		GridBagConstraints gbc = new GridBagConstraints();
		
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.weightx = 1;
		gbc.weighty = 1;
		gbc.gridy = 1;
		
		if(this.messageViewerLayout != null)
		{
			this.remove(this.messageViewerLayout);
		}
		
		this.messageViewerLayout = newLayout;
		
		this.add(this.messageViewerLayout, gbc);
		
		this.repaint();
		this.validate();
	}
	
	private class VerticalLayout extends JSplitPane
	{
		public VerticalLayout(MessageViewerPanel requestViewer, MessageViewerPanel responseViewer)
		{
			super(JSplitPane.VERTICAL_SPLIT);
			this.setResizeWeight(0.5);
			this.setTopComponent(requestViewer);
			this.setBottomComponent(responseViewer);
		}
	}
	
	private class HorizontalLayout extends JSplitPane
	{
		public HorizontalLayout(MessageViewerPanel requestViewer, MessageViewerPanel responseViewer)
		{
			super(JSplitPane.HORIZONTAL_SPLIT);
			this.setResizeWeight(0.5);
			this.setLeftComponent(requestViewer);
			this.setRightComponent(responseViewer);
		}
	}
	
	private class TabLayout extends JTabbedPane
	{
		public TabLayout(MessageViewerPanel requestViewer, MessageViewerPanel responseViewer)
		{
			this.add("Request", requestViewer);
			this.add("Response", responseViewer);
		}
	}
}
