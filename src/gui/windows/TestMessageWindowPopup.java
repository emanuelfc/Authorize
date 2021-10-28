package gui.windows;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import authorize.messages.TestMessage;
import burp.BurpExtender;
import gui.tables.TestsTable;

public class TestMessageWindowPopup implements MouseListener
{
	private TestsTable testsTable;
	
	public TestMessageWindowPopup(TestsTable testsTable)
	{
		this.testsTable = testsTable;
	}

	@Override
	public void mouseClicked(MouseEvent e)
	{
		if(e.getClickCount() == 2)
		{
			int index = this.testsTable.tableRowToMessageId(this.testsTable.getSelectedRow());
			TestMessage testMessage = BurpExtender.instance.getAuthorize().getTests().get(index);
			TestMessageWindow messageWindow = new TestMessageWindow(testMessage);
			messageWindow.setVisible(true);
		}
	}

	@Override
	public void mousePressed(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseReleased(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseEntered(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseExited(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}
}
