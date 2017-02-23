// oPenCrypt1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "oPenBase.h"


int main(int argc, char ** argv)
{

	oPenBase *base = new oPenBase();
	base->fPath= "C:\\libi\\idevice_id.exe";
	base->LoadExe();
	base->CryptearText();

}


