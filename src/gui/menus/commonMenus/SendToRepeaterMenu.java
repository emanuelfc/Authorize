package gui.menus.commonMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;

@SuppressWarnings("serial")
public class SendToRepeaterMenu extends JMenuItem
{
	public SendToRepeaterMenu(IHttpRequestResponse messageInfo)
	{
		this.setText("Send to Repeater");
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				IHttpService httpService = messageInfo.getHttpService();
				BurpExtender.callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), httpService.getProtocol().equals("https"), messageInfo.getRequest(), null);
			}
			
		});
	}
}
