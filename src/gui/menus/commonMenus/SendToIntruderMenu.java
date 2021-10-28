package gui.menus.commonMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;

@SuppressWarnings("serial")
public class SendToIntruderMenu extends JMenuItem
{
	public SendToIntruderMenu(IHttpRequestResponse messageInfo)
	{
		this.setText("Send to Intruder");
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				IHttpService httpService = messageInfo.getHttpService();
				BurpExtender.callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), httpService.getProtocol().equals("https"), messageInfo.getRequest(), null);
			}
			
		});
	}
}
