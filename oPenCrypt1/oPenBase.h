#pragma once

#include <string.h>
#include <iostream>
#include <stdio.h>
#include<Windows.h>

using namespace std;

class oPenBase
{	

private:	
	
public:

	oPenBase();
	DWORD Align(DWORD num, DWORD realSiz);
	~oPenBase();
	int Banner();
	int LoadExe();

};

