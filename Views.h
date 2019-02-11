#if !defined(AFX_VIEWS_H__20020629_8D64_963C_A351_0080AD509054__INCLUDED_)
#define AFX_VIEWS_H__20020629_8D64_963C_A351_0080AD509054__INCLUDED_

#include <iostream>
#include <fstream> 
#include "utf8conv.h"
#include "Thread.h"
#include "logger.h"
#ifdef _WIN64

#else
#include "backend/pack_x86.h"
#endif
//#include "svn_version.h"

using namespace std;
using namespace utf8util;
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


LogMessage* LogMessage::m_Instance = 0;
LogMessage* LogMessage::CreateInstance(HWND window)
{
	if (0 == m_Instance)
	{
		m_Instance = new LogMessage();
		m_Instance->init(window);
	}
	return m_Instance;
}

LogMessage* LogMessage::GetSingleton() { return m_Instance; }

void LogMessage::clear()
{
	if (listbox)
	{
		listbox.DeleteAllItems();
	}

}

void LogMessage::init(HWND hwnd)
{
	if (hwnd)
	{
		CImageList imglist;
		CIcon ico_info, ico_error, ico_warning, ico_success;
		ico_info.LoadIcon(IDI_INFO);
		ico_error.LoadIcon(IDI_ERR);
		ico_warning.LoadIcon(IDI_WARN);
		ico_success.LoadIcon(IDI_SUCCESS);
		imglist.Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 1);
		imglist.AddIcon(ico_success);
		imglist.AddIcon(ico_info);
		imglist.AddIcon(ico_warning);
		imglist.AddIcon(ico_error);
		window_hwnd = hwnd;
		listbox = GetDlgItem(window_hwnd, IDC_LOG);
		listbox.SetImageList(imglist.m_hImageList, LVSIL_SMALL);
		listbox.AddColumn(L"Description", 0);
		listbox.SetColumnWidth(0, 300);
		DoLogMessage(L"Welcome to mupack!", ERR_INFO);
	}
}

LogMessage::LogMessage(void)
{

}

LogMessage::~LogMessage(void)
{

}


enum COLOR
{
	// Text foreground colors
	// Standard text colors
	GRAY_TEXT = 8, BLUE_TEXT, GREEN_TEXT,
	TEAL_TEXT, RED_TEXT, PINK_TEXT,
	YELLOW_TEXT, WHITE_TEXT,
	// Faded text colors
	BLACK_TEXT = 0, BLUE_FADE_TEXT, GREEN_FADE_TEXT,
	TEAL_FADE_TEXT, RED_FADE_TEXT, PINK_FADE_TEXT,
	YELLOW_FADE_TEXT, WHITE_FADE_TEXT,
	// Standard text background color
	GRAY_BACKGROUND = GRAY_TEXT << 4, BLUE_BACKGROUND = BLUE_TEXT << 4,
	GREEN_BACKGROUND = GREEN_TEXT << 4, TEAL_BACKGROUND = TEAL_TEXT << 4,
	RED_BACKGROUND = RED_TEXT << 4, PINK_BACKGROUND = PINK_TEXT << 4,
	YELLOW_BACKGROUND = YELLOW_TEXT << 4, WHITE_BACKGROUND = WHITE_TEXT << 4,
	// Faded text background color
	BLACK_BACKGROUND = BLACK_TEXT << 4, BLUE_FADE_BACKGROUND = BLUE_FADE_TEXT << 4,
	GREEN_FADE_BACKGROUND = GREEN_FADE_TEXT << 4, TEAL_FADE_BACKGROUND = TEAL_FADE_TEXT << 4,
	RED_FADE_BACKGROUND = RED_FADE_TEXT << 4, PINK_FADE_BACKGROUND = PINK_FADE_TEXT << 4,
	YELLOW_FADE_BACKGROUND = YELLOW_FADE_TEXT << 4, WHITE_FADE_BACKGROUND = WHITE_FADE_TEXT << 4
};

void LogMessage::DoLogMessage(TCHAR* message, int warnlevel)
{
	if (listbox)
	{
		int amount_items = listbox.GetItemCount();
		listbox.AddItem(amount_items, 0, message, warnlevel);
	}
	else
	{
		HANDLE stdouthandle = GetStdHandle(STD_OUTPUT_HANDLE);
		switch (warnlevel)
		{
		case ERR_INFO:
			SetConsoleTextAttribute(stdouthandle, WHITE_FADE_TEXT);
			fprintf(stdout, "%s\n", message);
			break;
		case ERR_WARNING:
			SetConsoleTextAttribute(stdouthandle, YELLOW_TEXT);
			fprintf(stdout, "%s\n", message);
			break;
		case ERR_ERROR:
			SetConsoleTextAttribute(stdouthandle, RED_TEXT);
			fprintf(stdout, "%s\n", message);
			break;
		case ERR_SUCCESS:
			SetConsoleTextAttribute(stdouthandle, GREEN_TEXT);
			fprintf(stdout, "%s\n", message);
			break;
		}
	}
}

class CProcessThread : public CThreadImpl<CProcessThread>
{
	HWND m_hWndParent;
	TCHAR * exe_path;

public:
	CProcessThread(HWND hWndParent, TCHAR * path)
		: m_hWndParent(hWndParent)
	{
		exe_path = _tcsdup(path);
	}
	~CProcessThread()
	{
		free(exe_path);
	}

	DWORD Run()
	{
		LogMessage* message = LogMessage::GetSingleton();
		message->DoLogMessage(L"Processing. Please wait.", ERR_INFO);
		compress_file(exe_path);
		return 0;
	}
};



class CPackDlg : public CDialogImpl<CPackDlg>, public CDropFileTarget<CPackDlg>
{
	const TCHAR * list_name;
	CListViewCtrl listbox;
	CEdit file_pathedit;
	CProcessThread * process_thread;
	LogMessage * messages;
public:
	enum { IDD = IDD_MAIN };
	enum { TIMERID = 1337L };


	BEGIN_MSG_MAP(CPackDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialogView1)
		MESSAGE_HANDLER(WM_TIMER, OnTimer)
		COMMAND_ID_HANDLER(IDCANCEL, OnCancel)
		CHAIN_MSG_MAP(CDropFileTarget<CPackDlg>)
	END_MSG_MAP()

	CPackDlg() : process_thread(NULL) { }

	LRESULT OnInitDialogView1(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		file_pathedit = GetDlgItem(IDC_PATH);
		file_pathedit.SetWindowText(L"I'm gonna wreck it!");
		messages = LogMessage::CreateInstance(m_hWnd);
		RegisterDropTarget();
		return TRUE;
	}


	LRESULT OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		if (process_thread)
		{
			MessageBox(L"Please wait for the current job to complete.", L"Warning", MB_ICONINFORMATION);
			return 0;
		}
		return 0;
	}

	LRESULT OnTimer(UINT /*uMsg*/, WPARAM wParam, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		if (wParam == TIMERID)
		{
			if (process_thread && process_thread->Join(10) == WAIT_OBJECT_0)
			{
				delete process_thread;
				process_thread = NULL;
				KillTimer(TIMERID);
				file_pathedit.SetWindowText(L"Packing job complete.");
			}
		}

		return 0;
	}



	void ProcessFile(LPCTSTR lpszPath)
	{
		LogMessage* message = LogMessage::GetSingleton();
		message->clear();
		if (process_thread)
		{

			message->DoLogMessage(L"Please wait for the current job to complete.", ERR_ERROR);
			return;
		}
		file_pathedit.SetWindowText(lpszPath);
		process_thread = new CProcessThread(m_hWnd, (TCHAR*)lpszPath);
		message->DoLogMessage(L"Started packing thread.", ERR_INFO);
		file_pathedit.SetWindowText(L"Packing job in progress...");
		SetTimer(TIMERID, 100);
	}


};

class CAboutDlg : public CDialogImpl<CAboutDlg>
{
	CHyperLink website;
	CStatic version_number;
	CStatic builddate;
	CEdit greets;
public:
	enum { IDD = IDD_ABOUT };
	BEGIN_MSG_MAP(CAboutDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialogView1)
	END_MSG_MAP()

	CAboutDlg() { }

	LRESULT OnInitDialogView1(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		//CString verinf0 = SVN_REVISION;
		CString date = "Built on " __DATE__ " at " __TIME__ " (GMT+10)";
#ifndef  DEMO
		CString verinfo = "mupack2 public build";
#else // ! DEMO
		CString verinfo = "mupack public Exetools.com build.";
#endif


		CString greetz;

		greets = GetDlgItem(IDC_CREDITS);
		builddate = GetDlgItem(IDC_BUILDDATE);
		builddate.SetWindowText(date);
		version_number = GetDlgItem(IDC_MUPACKVER);
		version_number.SetWindowText(verinfo);

		greetz += "Igor Pavlov\r\n";
		greetz += "Shigeo 'herumi' Mitsunari\r\n";
		greetz += "Fabian 'ryg' Geisen\r\n";
		greetz += "Chris 'kode54' Snowhill\r\n";
		greetz += "Olav '8bitbubsy' Sørensen\r\n";
		greetz += "Lars 'zao' Viklund\r\n";
		greetz += "Janne 'Case' Hyvärinen\r\n";
		greetz += "João Marques\r\n";
		greetz += "Duncan 'Mr. eXoDia' Ogilvie and the x64dbg team\r\n";
		greetz += "The reversing group on Skype ;) \r\n";



		greets.SetWindowText(greetz);
		website.SubclassWindow(GetDlgItem(IDC_WEBSITE));
		website.SetHyperLink(_T("http://forum.exetools.com/showthread.php?t=17028"));
		return TRUE;
	}
};

#endif // !defined(AFX_VIEWS_H__20020629_8D64_963C_A351_0080AD509054__INCLUDED_)
