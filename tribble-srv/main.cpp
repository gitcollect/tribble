#include "tribble-srv.hpp"
SAMPFUNCS *SF = new SAMPFUNCS();

void pprintf(const char *format, ...)
{
	char buf[128];
	va_list args;

	va_start(args, format);

	sprintf_s(buf, 128, PROGRAM_NAME": ");
	vsnprintf(buf + strlen(buf), 128 - strlen(buf), format, args);

	va_end(args);

	SF->getSAMP()->getChat()->AddChatMessage(D3DCOLOR_XRGB(0xFF, 0xFF, 0xAFF), buf);
}

static void version()
{
	char buf[1024];

	sprintf_s(buf, 1024,
		PROGRAM_NAME " " PROGRAM_VERSION "\n\n"
		"Copyright (c) 2016 " PROGRAM_AUTHORS "\n"
		"\n"
		"This is free software: you are free to change and redistribute it.\n"
		"This project is released under the MIT license.\n"
		"\n"
		"Report bugs to: " PROGRAM_BUGREPORT_EMAIL "\n"
		"" PROGRAM_NAME " home page: <" PROGRAM_WEBSITE ">\n"
		);

	SF->getSAMP()->getDialog()->ShowDialog(1, 0, "weaponfinder", buf, "Hide", "");
	return;
}

static void usage()
{
	char buf[2048];

	sprintf_s(buf, 2048,
		"tribble is a fuzzer that uses runtime instrumentation\n"
		"to find vulnerabilities in San Andreas: Multiplayer scripts.\n\n"
		"\t/weaponfinder save [directory]\n\t\tturn corpus generation on or off\n"
		"\t\tcorpus data will be saved to corpora/[directory]\n"
		HELP_OPTION_DESCRIPTION
		VERSION_OPTION_DESCRIPTION
		);

	SF->getSAMP()->getDialog()->ShowDialog(1, 0, "tribble", buf, "Hide", "");
	return;
}

void CALLBACK cmd_tribble(std::string param)
{
	char *param_str = _strdup(param.c_str());
	char *token = NULL;

	token = strtok(param_str, " ");

	if (param.empty() || !_strcmpi(param_str, "help"))
		usage();
	else if (!_strcmpi(param_str, "version"))
		version();
	else if (!_strcmpi(param_str, "save"))
		tog_saving(strtok(NULL, ""));
	else if (!_strcmpi(param_str, "mutate")) {
		token = strtok(NULL, "");
		fuzz_mutate(token, strlen(token));
	}
	else
		usage();
}

void CALLBACK mainloop()
{
	static bool init = false;

	if (!init) {
		if (GAME == nullptr)
			return;
		if (GAME->GetSystemState() != eSystemState::GS_PLAYING_GAME)
			return;
		if (!SF->getSAMP()->IsInitialized())
			return;

		pprintf("tribble-srv " PROGRAM_VERSION " has been loaded, use /tribble-srv for general help.");
		SF->getSAMP()->registerChatCommand("tribble-srv", cmd_tribble);
		SF->getRakNet()->registerRakNetCallback(RakNetScriptHookType::RAKHOOK_TYPE_OUTCOMING_RPC, hook_save_corpus);
		init = true;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReasonForCall, LPVOID lpReserved)
{
	switch (dwReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		SF->initPlugin(mainloop, hModule);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
