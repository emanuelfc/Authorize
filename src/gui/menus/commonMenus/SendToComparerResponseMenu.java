package gui.menus.commonMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class SendToComparerResponseMenu extends JMenuItem
{
	public SendToComparerResponseMenu(IHttpRequestResponse messageInfo)
	{
		this.setText("Send to Comparer (Response)");
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				BurpExtender.callbacks.sendToComparer(messageInfo.getResponse());
			}
			
		});
	}
}
