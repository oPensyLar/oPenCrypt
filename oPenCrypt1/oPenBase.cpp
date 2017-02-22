#include "stdafx.h"
#include "oPenBase.h"


oPenBase::oPenBase()
{
}

DWORD oPenBase::Align(DWORD num, DWORD realSiz)
{


	return 0;
}


oPenBase::~oPenBase()
{

}



int oPenBase::Banner()
{
	//cout << ("oPenMorfosis v1.0.0 Ofusca PE files con codigo polimorfico\nCopyright (c) 2017, DevelSecurity - oPen syLar <vgomez@develsecurity.co.ve>\n\n");
	return 0;

}

int oPenBase::LoadExe()
{

	char exePath[] = "C:\\libi\\idevice_id.exe";
	HANDLE hFile;

	//Abre y obtiene el handle para poder jugar
	hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == NULL)
		return -1;

	unsigned long d;
	IMAGE_DOS_HEADER imgDosHeader;

	//Lee solo el header DOS
	if (!ReadFile(hFile, (void *)&imgDosHeader, sizeof(imgDosHeader), &d, NULL))
	{
		cout << "[!] IMPOSSIBLE read header dos";
		return 1;
	}

	if (imgDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "[!] INVALID dos signature";
		return 2;
	}	

	SetFilePointer(hFile, imgDosHeader.e_lfanew, NULL, FILE_BEGIN);

	IMAGE_NT_HEADERS imgNtHeaders;

	//Lee solo el header NT
	if (!ReadFile(hFile, (void *)&imgNtHeaders, sizeof(imgNtHeaders), &d, NULL))
	{
		cout << "[!] IMPOSSIBLE read header NT";
		return 1;
	}



	if (imgNtHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "[!] INVALID NT signature";
		return 4;
	}

	//cout << "[+] NumberOfSections 0x" << std::hex << imgNtHeaders.FileHeader.NumberOfSections << endl;
	//cout << "[+] DataDirectory 0x" << std::hex << imgNtHeaders.OptionalHeader.DataDirectory << endl;
	//cout << "[+] MajorImageVersion 0x" << std::hex << imgNtHeaders.OptionalHeader.MajorImageVersion << endl;
	//cout << "[+] MinorOperatingSystemVersion 0x" << std::hex << imgNtHeaders.OptionalHeader.MinorOperatingSystemVersion << endl;
	//cout << "[+] MinorLinkerVersion 0x" << std::hex << imgNtHeaders.OptionalHeader.MinorLinkerVersion << endl;
	//cout << "[+] MajorOperatingSystemVersion 0x" << std::hex << imgNtHeaders.OptionalHeader.MajorOperatingSystemVersion << endl;
	//cout << "[+] TimeDateStamp 0x" << std::hex << imgNtHeaders.FileHeader.TimeDateStamp << endl;
	//cout << "[+] Machine 0x" << std::hex << imgNtHeaders.FileHeader.Machine << endl;
	//cout << "[+] Reading Sections "  << imgNtHeaders.OptionalHeader.SizeOfHeaders << endl;

	//Reserva mem para todo y cada una de las secciones
	IMAGE_SECTION_HEADER * imgSectionHeader;	


	imgSectionHeader = (IMAGE_SECTION_HEADER *)GlobalAlloc(GMEM_FIXED, sizeof(IMAGE_SECTION_HEADER) * imgNtHeaders.FileHeader.NumberOfSections);


	ReadFile(hFile, (void *)imgSectionHeader, sizeof(IMAGE_SECTION_HEADER)*imgNtHeaders.FileHeader.NumberOfSections, &d, NULL);

	for (int i = 0; i <  imgNtHeaders.FileHeader.NumberOfSections; i++)
	{
		printf("%s\n", imgSectionHeader[i].Name);
		printf("RVA 0x%x\n\n", imgSectionHeader[i].VirtualAddress);
	}

	return 0;
}