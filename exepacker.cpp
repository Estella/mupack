// drivercfg.cpp : main source file for drivercfg.exe
//

#include "stdafx.h"
#include "MainDlg.h"
#include <shellapi.h>
#include <windows.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <fstream>
#include "Views.h"
CAppModule _Module;
#include <algorithm>



// maximum mumber of lines the output console should have

static const WORD MAX_CONSOLE_LINES = 1000;

void RedirectIOToConsole()
{
	long lStdHandle;
	FILE *fp;
	int hConHandle;
	CONSOLE_SCREEN_BUFFER_INFO coninfo;
	// set the screen buffer to be big enough to let us scroll text
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &coninfo);
	coninfo.dwSize.Y = MAX_CONSOLE_LINES;
	SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE),
		coninfo.dwSize);
	// redirect unbuffered STDOUT to the console
	lStdHandle = (long)GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
	fp = _fdopen(hConHandle, "w");
	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}


class CProcessThread_Console : public CThreadImpl<CProcessThread_Console>
{
	TCHAR * exe_path;

public:
	CProcessThread_Console(TCHAR * path)
	{
		exe_path = _tcsdup(path);
	}
	~CProcessThread_Console()
	{
		free(exe_path);
	}

	DWORD Run()
	{
		LogMessage* message = LogMessage::GetSingleton();
		message->DoLogMessage(L"Processing. Please wait.", ERR_SUCCESS);
		compress_file(exe_path);
		return 0;
	}
};



int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR lpstrCmdLine, int nCmdShow)
{
	int argc = __argc;
	char** argv = __argv;
	if (argc < 2)
	{
		if (!AttachConsole(ATTACH_PARENT_PROCESS))
		{
			HRESULT hRes = ::CoInitialize(NULL);
			// If you are running on NT 4.0 or higher you can use the following call instead to 
			// make the EXE free threaded. This means that calls come in on a random RPC thread.
			//	HRESULT hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
			ATLASSERT(SUCCEEDED(hRes));
			// this resolves ATL window thunking problem when Microsoft Layer for Unicode (MSLU) is used
			::DefWindowProc(NULL, 0, 0, 0L);
			AtlInitCommonControls(ICC_BAR_CLASSES);	// add flags to support other controls
			hRes = _Module.Init(NULL, hInstance);
			ATLASSERT(SUCCEEDED(hRes));
			CMessageLoop theLoop;
			_Module.AddMessageLoop(&theLoop);
			CMainDlg dlgMain;
			if (dlgMain.Create(NULL) == NULL)
			{
				ATLTRACE(_T("Main dialog creation failed!\n"));
				return 0;
			}
			dlgMain.ShowWindow(nCmdShow);
			int nRet = theLoop.Run();
			_Module.RemoveMessageLoop();
			_Module.Term();
			::CoUninitialize();
			return nRet;
		}
		else
		{
			RedirectIOToConsole();
			printf("\n"
				" Usage: %s <exe/dll to compress>\n"
				"\n"
				" Simply specify a Win32 EXE/DLL to compress. Its that simple.\n"
				"\n"
				" Usage example: mupack.exe c:\\test.exe\n"
				"\n", argv[0]);

			if (GetConsoleWindow() == GetForegroundWindow()) {
				INPUT ip;
				// Set up a generic keyboard event.
				ip.type = INPUT_KEYBOARD;
				ip.ki.wScan = 0; // hardware scan code for key
				ip.ki.time = 0;
				ip.ki.dwExtraInfo = 0;

				// Send the "Enter" key
				ip.ki.wVk = 0x0D; // virtual-key code for the "Enter" key
				ip.ki.dwFlags = 0; // 0 for key press
				SendInput(1, &ip, sizeof(INPUT));

				// Release the "Enter" key
				ip.ki.dwFlags = KEYEVENTF_KEYUP; // KEYEVENTF_KEYUP for key release
				SendInput(1, &ip, sizeof(INPUT));
			}

			return 0;
		}
	}
	if (!AttachConsole(ATTACH_PARENT_PROCESS))AllocConsole();
	RedirectIOToConsole();
	WORD   index = 0;
	// Remember how things were when we started
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo((HANDLE)GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	LogMessage *messages = LogMessage::CreateInstance(NULL);
	printf("\n");
	CProcessThread_Console*process_thread = new CProcessThread_Console((TCHAR*)argv[1]);
	process_thread->Join(INFINITE);
	delete process_thread;
	process_thread = NULL;


	SetConsoleTextAttribute((HANDLE)GetStdHandle(STD_OUTPUT_HANDLE), csbi.wAttributes);
	if (GetConsoleWindow() == GetForegroundWindow()) {
		INPUT ip;
		// Set up a generic keyboard event.
		ip.type = INPUT_KEYBOARD;
		ip.ki.wScan = 0; // hardware scan code for key
		ip.ki.time = 0;
		ip.ki.dwExtraInfo = 0;

		// Send the "Enter" key
		ip.ki.wVk = 0x0D; // virtual-key code for the "Enter" key
		ip.ki.dwFlags = 0; // 0 for key press
		SendInput(1, &ip, sizeof(INPUT));

		// Release the "Enter" key
		ip.ki.dwFlags = KEYEVENTF_KEYUP; // KEYEVENTF_KEYUP for key release
		SendInput(1, &ip, sizeof(INPUT));
	}
	return 0;
}
