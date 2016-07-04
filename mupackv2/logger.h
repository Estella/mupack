#include "resource.h"

enum log_err{
	ERR_SUCCESS = 0,
	ERR_INFO = 1,
	ERR_WARNING = 2,
	ERR_ERROR = 3
};

class LogMessage
{
public:
	static	LogMessage*				CreateInstance						(HWND window) ;
	static	LogMessage*				GetSingleton						( ) ;
	void                            init(HWND hwnd);
	void					        DoLogMessage						( TCHAR* message,int warnlevel ) ;
	void                            clear();
	~LogMessage							(void);
private:
	LogMessage							(void);
	CListViewCtrl listbox;
	HWND control_hwnd;
	HWND window_hwnd;
	static	LogMessage*	m_Instance;
};

