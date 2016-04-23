#pragma once

typedef struct corpus_data corpus_data;
struct corpus_data
{
	bool saving_enabled;
	char directory_name[MAX_PATH];
};

void tog_saving(char *dir);
bool CALLBACK hook_save_corpus(stRakNetHookParams *params);
