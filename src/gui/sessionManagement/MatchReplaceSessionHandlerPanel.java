package gui.sessionManagement;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JToggleButton;
import authorize.sessionManagement.MatchReplaceSessionHandler;
import gui.RequestSessionHandlerPanel;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class MatchReplaceSessionHandlerPanel extends AbstractEntityPanel
{
	public static final String ADD_RESPONSE = "Add Response Session Extractor";
	public static final String REMOVE_RESPONSE = "Remove Response Session Extractor";
	
	private RequestSessionHandlerPanel requestPanel;
	private JToggleButton responsePanelButton;
	private ResponseSessionExtractorPanel responsePanel;
	
	private MatchReplaceSessionHandlerPanel(RequestSessionHandlerPanel requestPanel, ResponseSessionExtractorPanel responsePanel)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = super.createBaseConstraints();
		gbc.gridwidth = 2;
		
		this.requestPanel = requestPanel;
		super.addComponent(this.requestPanel, gbc);
		
		this.responsePanelButton = new JToggleButton();
		
		this.responsePanel = responsePanel;
		if(this.responsePanel != null)
		{
			this.responsePanelButton.setText(REMOVE_RESPONSE);
			this.responsePanelButton.setSelected(true);
		}
		else
		{
			this.responsePanelButton.setText(ADD_RESPONSE);
		}
		
		this.responsePanelButton.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(MatchReplaceSessionHandlerPanel.this.responsePanelButton.isSelected())
				{				
					MatchReplaceSessionHandlerPanel.this.responsePanel = new ResponseSessionExtractorPanel();
					MatchReplaceSessionHandlerPanel.super.addComponent(MatchReplaceSessionHandlerPanel.this.responsePanel, gbc);
					
					responsePanelButton.setText(REMOVE_RESPONSE);
				}
				else
				{
					MatchReplaceSessionHandlerPanel.this.remove(MatchReplaceSessionHandlerPanel.this.responsePanel);
					MatchReplaceSessionHandlerPanel.this.responsePanel = null;
					
					responsePanelButton.setText(ADD_RESPONSE);
				}
			}
			
		});
		super.addComponent(this.responsePanelButton, gbc);
		
		if(this.responsePanel != null)
		{
			super.addComponent(this.responsePanel, gbc);
		}
	}
	
	public MatchReplaceSessionHandlerPanel(MatchReplaceSessionHandler sessionHandler)
	{
		this(new RequestSessionHandlerPanel(sessionHandler), sessionHandler.getResponseSessionExtractor() !=  null ? new ResponseSessionExtractorPanel(sessionHandler.getResponseSessionExtractor()) : null);
	}
	
	public MatchReplaceSessionHandlerPanel()
	{
		this(new RequestSessionHandlerPanel(), null);
	}
	
	public MatchReplaceSessionHandler create()
	{
		MatchReplaceSessionHandler sessionHandler = this.requestPanel.create();
		if(this.responsePanelButton.isSelected())
		{
			sessionHandler.setResponseSessionExtractor(this.responsePanel.create());
		}
		
		return sessionHandler;
	}
	
	public void edit(MatchReplaceSessionHandler sessionHandler)
	{
		this.requestPanel.edit(sessionHandler);
		if(this.responsePanelButton.isSelected())
		{
			this.responsePanel.edit(sessionHandler.getResponseSessionExtractor());
		}
		else sessionHandler.setResponseSessionExtractor(null);
	}
}
