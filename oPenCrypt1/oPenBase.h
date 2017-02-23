#pragma once

#include<stdio.h> 
#include<windows.h>
#include<time.h>
#include<tchar.h>
#include<string>
#include<iostream>


using namespace std;

class oPenBase
{	

private:	
	LPVOID lpBase;                      //Pointer to the base memory of mapped file
	PIMAGE_SECTION_HEADER pSecHeader;   //Section Header or Section Table Header
	PIMAGE_NT_HEADERS ntHeader;         //Pointer to NT Header
	HANDLE hMapObject;
	
public:

	string errStr;
	LPCSTR fPath;

	oPenBase();
	~oPenBase();
	int Banner();
	int CryptearText();
	int LoadExe();

	void HexDump(char * p, int size, int secAddress);

};

