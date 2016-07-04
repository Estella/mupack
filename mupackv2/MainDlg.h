// MainDlg.h : interface of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////
#include <atlframe.h>
#include <atlctrls.h>
#include <atldlgs.h>
#include <atlwin.h>
#include "resource.h"
#include "DlgTabCtrl.h"
#include "DropFileTarget.h"
#include "Views.h"


#pragma once

class CMainDlg : public CDialogImpl<CMainDlg>, public CUpdateUI<CMainDlg>,
		public CMessageFilter, public CIdleHandler
{
public:
	enum { IDD = IDD_MAINDLG };
	CDialogTabCtrl m_ctrlTab;
	CPackDlg m_view1;
	CAboutDlg m_view3;

	virtual BOOL PreTranslateMessage(MSG* pMsg)
	{
		return CWindow::IsDialogMessage(pMsg);
	}

	virtual BOOL OnIdle()
	{
		return FALSE;
	}

	BEGIN_UPDATE_UI_MAP(CMainDlg)
	END_UPDATE_UI_MAP()

	BEGIN_MSG_MAP(CMainDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		MESSAGE_HANDLER(WM_DESTROY, OnDestroy)
		COMMAND_ID_HANDLER(IDOK, OnOK)
		COMMAND_ID_HANDLER(IDCANCEL, OnCancel)
		REFLECT_NOTIFICATIONS();
	END_MSG_MAP()

// Handler prototypes (uncomment arguments if needed):
//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// center the dialog on the screen
		CenterWindow();
		// set icons
		CImageList imglist;
		CIcon mupack,abouticon;
		mupack.LoadIcon(IDI_COMPRESS);
		abouticon.LoadIcon(IDI_ABOUT);
		imglist.Create(16,16, ILC_COLOR32 | ILC_MASK, 1, 1);
		imglist.AddIcon(mupack);
		imglist.AddIcon(abouticon);
		m_ctrlTab.SubclassWindow(GetDlgItem(IDC_TAB));
		m_view1.Create(m_hWnd);
		m_view3.Create(m_hWnd);
		m_ctrlTab.SetImageList(imglist.m_hImageList);
		TCITEM tci = { 0 };
		tci.mask = TCIF_TEXT | TCIF_IMAGE;
		tci.pszText = _T("Pack");
		tci.iImage = 0;
		m_ctrlTab.InsertItem(0, &tci, m_view1);
		tci.mask = TCIF_TEXT | TCIF_IMAGE;
		tci.pszText = _T("About");
		tci.iImage = 1;
		m_ctrlTab.InsertItem(1, &tci, m_view3);
		m_ctrlTab.SetCurSel(0);
		// register object for message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->AddMessageFilter(this);
		pLoop->AddIdleHandler(this);

		UIAddChildWindowContainer(m_hWnd);

		return TRUE;
	}

	LRESULT OnDestroy(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// unregister message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->RemoveMessageFilter(this);
		pLoop->RemoveIdleHandler(this);

		return 0;
	}

	LRESULT OnOK(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		// TODO: Add validation code 
		CloseDialog(wID);
		return 0;
	}

	LRESULT OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CloseDialog(wID);
		return 0;
	}

	void CloseDialog(int nVal)
	{
		DestroyWindow();
		::PostQuitMessage(nVal);
	}
};
