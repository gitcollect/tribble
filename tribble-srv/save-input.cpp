#include "tribble-srv.hpp"
static corpus_data data;

void tog_saving(char *dir)
{
	int dir_ret;
	char real_path[MAX_PATH];

	if (data.saving_enabled) {
		data.saving_enabled = false;
		pprintf("{ff0000}Saving{ffffff} disabled.");
		return;
	}

	if (dir != NULL) {
		_snprintf_s(real_path, MAX_PATH, "%s/tribble-srv/corpora/%s", getenv("APPDATA"), dir);
		dir_ret = CreateDirectory(real_path, NULL);

		if (dir_ret == 0 && GetLastError() != ERROR_ALREADY_EXISTS)
			return pprintf("There's been a problem creating the directory (#%d).", GetLastError());
	}
	else {
		_snprintf_s(real_path, MAX_PATH, "%s/tribble-srv/corpora", getenv("APPDATA"));
	}

	strncpy(data.directory_name, real_path, MAX_PATH);
	data.directory_name[MAX_PATH - 1] = '\0';
	data.saving_enabled = true;

	pprintf("{00ff00}Saving{ffffff} corpus data to %s.", data.directory_name);		
}

bool CALLBACK hook_save_corpus(stRakNetHookParams* params)
{
	char cmd_text[128];
	char path[MAX_PATH];
	int cmd_len = -1;
	char *ip_addr, *token;
	FILE *fcorpus;

	if (!data.saving_enabled) return true;

	if (params->packetId == RPCEnumeration::RPC_ServerCommand) {
		params->bitStream->ResetReadPointer();
		params->bitStream->Read(cmd_len);
		params->bitStream->Read(cmd_text, cmd_len);
		params->bitStream->ResetReadPointer();
		cmd_text[cmd_len] = '\0';

		ip_addr = SF->getSAMP()->getInfo()->szIP;

		token = strchr(cmd_text, ' ');

		pprintf("ip_addr: %s", ip_addr);
		pprintf("cmd: %s", &cmd_text[1]);

		if (token != NULL) {	// We have some arguments.
			*token = '\0';
			_snprintf_s(path, MAX_PATH, "%s/%s-%s.cases", data.directory_name, ip_addr, &cmd_text[1]);
			fcorpus = fopen(path, "a+");
			if (fcorpus == NULL) {
				pprintf("Unable to open %s (#%d)", path, errno);
				return true;
			}

			fprintf(fcorpus, token + 1);
			fprintf(fcorpus, "\n");
			fclose(fcorpus);
		}
	}
	return true;
}