#include "stdafx.h"
#include "About.h"

static BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam);
static void OnCommand (HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);
HWND credits;
LRESULT CALLBACK About(HWND hDlg,UINT uiMsg,WPARAM wParam,LPARAM lParam)
{
	switch (uiMsg) 
	{
	HANDLE_MSG(hDlg, WM_INITDIALOG,	OnInitDialog);
	HANDLE_MSG(hDlg, WM_COMMAND,	OnCommand);
	}
	return 0;
}
char *CreditsString[]={
	"Coded by mudlord\n"
	"Uses aplib by Joergen Ibsen\n"
	"Uses LZMA by Igor Pavlov\n"
};
/****************************************************************************
*								OnInitDialog
****************************************************************************/
static BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	credits=GetDlgItem(hwnd,IDC_CREDITS);
	SetWindowText(credits,*CreditsString);
	return TRUE;
}

/****************************************************************************
*								OnCommand
*
*  hwnd			Handle of window to which this message applies
*  id			Specifies the identifier of the menu item, 
*				control, or accelerator.
*  hwndCtl		Handle of the control sending the message if the message
*				is from a control, otherwise, this parameter is NULL. 
*  codeNotify	Specifies the notification code if the message is from 
*				a control.
*				This parameter is 1 when the message is from an 
*				accelerator.
*				This parameter is 0 when the message is from a menu.
****************************************************************************/
static void OnCommand (HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	switch (id) 
	{	/* id */
		case IDOK:
		case IDCANCEL:
			EndDialog(hwnd,(INT_PTR) &codeNotify);
			break;
		case IDC_WEB:
			WinExec("Explorer http://mudlord.info/", SW_SHOWMAXIMIZED);
			break;
	}/* id */
}
