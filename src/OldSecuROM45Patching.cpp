#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "NString.h"
#include "Utils.h"
#include "SecuROM345Patching.h"
#include "CRCFixer.h"
#include "Config.h"

extern Config config;

bool SecuROMPatchingDone = false;

void GeometryHookForSecuROM45()
{
	logc(FOREGROUND_GREEN, "SecuROM 4 + 5 Geometry Hook Called. Reversing Patches...\n");
	ReversePatches();
}

// #define WritePatchBYTE WriteProtectedBYTE
// #define WritePatchDWORD WriteProtectedDWORD

static bool GetSecuROMVersion(int *VersionMajor, int *VersionMinor, int *VersionRevision)
{
	bool ret = false;
	DWORD versionString = -1L;
	DWORD ExeAddr = (DWORD)GetModuleHandle(NULL);
	auto sections = GetSections(ExeAddr);
	for (auto& section : sections)
	{
		versionString = FindHexString(ExeAddr + section->VirtualAddress, ExeAddr + section->VirtualAddress + section->Misc.VirtualSize, "4164644403000000??2E????2E????00");
		if (versionString != -1L)
			break;
	}
	if (versionString != -1L)
	{
		if (sscanf((char*)(versionString + 8), "%01d.%02d.%02d", VersionMajor, VersionMinor, VersionRevision) == 3)
		{
			logc(FOREGROUND_GREEN, "SecuROM Version: %d.%02d.%02d\n", *VersionMajor, *VersionMinor, *VersionRevision);
			ret = true;
		}
	}
	return ret;
}

bool SecuROM45Patching()
{
	if (SecuROMPatchingDone)
	{
		logc(FOREGROUND_GREEN, "SecuROM 4/5 Patching Already Done.\n");
		return SecuROMPatchingDone;
	}

	int VersionMajor = 0, VersionMinor = 0, VersionRevision = 0;
	DWORD ExeAddr = (DWORD)GetModuleHandle(NULL);
	auto sections = GetSections(ExeAddr);
	if (GetSecuROMVersion(&VersionMajor, &VersionMinor, &VersionRevision))
	{
		logc(FOREGROUND_GREEN, "SecuROM Version: %d.%02d.%02d\n", VersionMajor, VersionMinor, VersionRevision);

		if (VersionMajor == 4 || VersionMajor == 5)
		{
			/*	00575CA5                            | EB CC                                 | jmp maxpayne2.575C73                             |
				00575CA7                            | A1 78FB5900                           | mov eax,dword ptr ds:[59FB78]                    | Good
				00575CAC                            | 3B05 ACBA6400                         | cmp eax,dword ptr ds:[64BAAC]                    | 0064BAAC:"/NYF"
				00575CB2                            | 0F85 89000000                         | jne maxpayne2.575D41                             | not taken
				00575CB8                            | 68 E0E66400                           | push maxpayne2.64E6E0    */
			bool gtaVCMethod = false;
			DWORD CDCheckSectionStart = -1, CDCheckSectionEnd = -1;
			std::vector<DWORD> FirstCDPatches;
			for (auto& section : sections)
			{
				CDCheckSectionStart = ExeAddr + section->VirtualAddress;
				CDCheckSectionEnd = ExeAddr + section->VirtualAddress + section->Misc.VirtualSize;
				FirstCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "3B??????????0F85????????68????????E8????????83C40485C0", "CD CHECK 1");
				if (FirstCDPatches.size() >= 1)
					break;
			}

			if (FirstCDPatches.size() == 0)
			{
				logc(FOREGROUND_YELLOW, "Failed to find CD Check 1 patch location in first pass. Trying again using a simpler match from GTA VC 1.0\n");
				for (auto& section : sections)
				{
					CDCheckSectionStart = ExeAddr + section->VirtualAddress;
					CDCheckSectionEnd = ExeAddr + section->VirtualAddress + section->Misc.VirtualSize;
					FirstCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "A1????????3B05????????75??68", "CD CHECK 1 (GTA VC)");
					if (FirstCDPatches.size() > 1)
					{
						gtaVCMethod = true;
						break;
					}
				}
			}

			if (FirstCDPatches.size() == 0)
			{
				logc(FOREGROUND_YELLOW, "Failed to find CD Check 1 patch location in first pass. Trying again using a simpler match from GTA VC 1.1\n");
				for (auto& section : sections)
				{
					CDCheckSectionStart = ExeAddr + section->VirtualAddress;
					CDCheckSectionEnd = ExeAddr + section->VirtualAddress + section->Misc.VirtualSize;
					FirstCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "A1????????3B05????????0F85????????68", "CD CHECK 1 (GTA VC 1.1)");
					if (FirstCDPatches.size() >= 1)
					{
						gtaVCMethod = true;
						break;
					}
				}
			}

			if (FirstCDPatches.size() >= 1)
			{
				logc(FOREGROUND_GREEN, "CD 1 Checks Found: %d\n", FirstCDPatches.size());

				if (gtaVCMethod)
				{
					logc(FOREGROUND_YELLOW, "Using GTA VC style CD Check 1 patching method\n");
					for (unsigned int i = 0; i < FirstCDPatches.size(); i++)
					{
						DWORD FirstCDPatch = FirstCDPatches[i];
						logc(FOREGROUND_GREEN, "Found CD Check 1 patch location at %08X\n", FirstCDPatch);

						// Might be a small jump or a long jump - NOP accordingly
						if (*(BYTE*)(FirstCDPatch + 0xB) == 0x75)
						{
							WritePatchBYTE(FirstCDPatch + 0xB, 0x90);
							WritePatchBYTE(FirstCDPatch + 0xC, 0x90);
						}
						else
						{
							WritePatchBYTE(FirstCDPatch + 0xB, 0x90);
							WritePatchBYTE(FirstCDPatch + 0xC, 0x90);
							WritePatchDWORD(FirstCDPatch + 0xD, 0x90909090);
						}

						DWORD Part2_SmallJMP = FindHexString(FirstCDPatch, CDCheckSectionEnd, "74", "Finding Part 2 of CD Check 1 Patch (NOP the next JE (small))");
						DWORD Part2_BigJMP = FindHexString(FirstCDPatch, CDCheckSectionEnd, "0F84", "Finding Part 2 of CD Check 1 Patch (NOP the next JE (big))");

						if (Part2_SmallJMP < Part2_BigJMP && Part2_BigJMP != -1L)
						{
							logc(FOREGROUND_YELLOW, "Patching Part 2 of 1: %08X (Risky Method! (Small JE))\n", Part2_SmallJMP);
							WritePatchBYTE(Part2_SmallJMP, 0x90);
							WritePatchBYTE(Part2_SmallJMP + 1, 0x90);
						}
						else
						{
							logc(FOREGROUND_YELLOW, "Patching Part 2 of 1: %08X (Risky Method! (Big JE))\n", Part2_BigJMP);
							WritePatchBYTE(Part2_SmallJMP, 0x90);
							WritePatchBYTE(Part2_SmallJMP + 1, 0x90);
							WritePatchDWORD(Part2_SmallJMP + 2, 0x90909090);
						}
					}
				}
				else
				{
					for (unsigned int i = 0; i < FirstCDPatches.size(); i++)
					{
						DWORD FirstCDPatch = FirstCDPatches[i];
						logc(FOREGROUND_GREEN, "Found CD Check 1 patch location at %08X\n", FirstCDPatch);
						WritePatchBYTE(FirstCDPatch + 6, 0x90);
						WritePatchBYTE(FirstCDPatch + 7, 0x90);
						WritePatchDWORD(FirstCDPatch + 8, 0x90909090);

						logc(FOREGROUND_GREEN, "Patching Part 2 of 1: %08X\n", FirstCDPatch + 0x1B);

						if (*((BYTE*)(FirstCDPatch + 0x1B)) == 0x0F)
						{
							WritePatchBYTE(FirstCDPatch + 0x1B, 0x90);
							WritePatchBYTE(FirstCDPatch + 0x1C, 0x90);
							WritePatchDWORD(FirstCDPatch + 0x1D, 0x90909090);
						}
						else
						{
							WritePatchBYTE(FirstCDPatch + 0x1B, 0x90);
							WritePatchBYTE(FirstCDPatch + 0x1C, 0x90);
						}
					}
				}
				
				GetKey(true);

				auto SecondCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "A1????????8B0A3B0C85????????7502EB118B", "CD CHECK 2");
				if (SecondCDPatches.size() >= 1)
				{
					logc(FOREGROUND_GREEN, "CD Check 2 Found: %d\n", SecondCDPatches.size());

					for (unsigned int i = 0; i < SecondCDPatches.size(); i++)
					{
						DWORD SecondCDPatch = SecondCDPatches[i];
						logc(FOREGROUND_GREEN, "Found CD Check 2 patch location at %08X\n", SecondCDPatch);
						WritePatchBYTE(SecondCDPatch + 0xE, 0x90);
						WritePatchBYTE(SecondCDPatch + 0xF, 0x90);
					}

					DWORD ThirdCDPatch = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, "81??9600000039??????????74??", "CD CHECK 3 (May not be present or needed)");
					if (ThirdCDPatch != -1L)
					{
						logc(FOREGROUND_GREEN, "Found CD Check 3 patch location at %08X\n", ThirdCDPatch);
						WritePatchBYTE(ThirdCDPatch + 0xC, 0xEB);
					}
					else
						logc(FOREGROUND_YELLOW, "Failed to find third CD Check patch location (This is optional)\n");

					DWORD GeometryCDPatch = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, "E8????????83C408DD1D????????E9", "Geometry CD Check");
					if (GeometryCDPatch != -1L)
					{
						logc(FOREGROUND_GREEN, "Found Geometry CD Check patch location at %08X\n", GeometryCDPatch);
						//WritePatchBYTE(GeometryCDPatch + 0x8, 0x90);
						//WritePatchBYTE(GeometryCDPatch + 0x9, 0x90);
						//WritePatchDWORD(GeometryCDPatch + 0xA, 0x90909090);

						WritePatchBYTE(GeometryCDPatch + 0x8, 0x90);
						WritePatchBYTE(GeometryCDPatch + 0x9, 0xE8);
						WritePatchDWORD(GeometryCDPatch + 0xa, (((DWORD)(GeometryHookForSecuROM45)) - (GeometryCDPatch + 0x9)) - 5);
					}
					else
					{
						logc(FOREGROUND_YELLOW, "Failed to find SAFE Geometry CD Check patch location. Trying a less safe search\n");

						GeometryCDPatch = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, "DD1D????????E8", "Geometry CD Check (GTA VC - less safe)");
						if (GeometryCDPatch != -1L)
						{
							logc(FOREGROUND_GREEN, "Found Unsafe Geometry CD Check patch location at %08X\n", GeometryCDPatch);
							//WritePatchBYTE(GeometryCDPatch + 0x0, 0x90);
							//WritePatchBYTE(GeometryCDPatch + 0x1, 0x90);
							//WritePatchDWORD(GeometryCDPatch + 0x2, 0x90909090);
							WritePatchBYTE(GeometryCDPatch + 0, 0x90);
							WritePatchBYTE(GeometryCDPatch + 1, 0xE8);
							WritePatchDWORD(GeometryCDPatch + 2, (((DWORD)(GeometryHookForSecuROM45)) - (GeometryCDPatch + 1)) - 5);

						}
						else
							logc(FOREGROUND_RED, "Failed to find any Geometry CD Check patch location!!!\n");
					}

					
					// GTA VC - Mouse fucking fix! (from https://github.com/CookiePLMonster/SilentPatch/blob/0cefc58fefd8fb4154130edeba69b169d930f78e/SilentPatchVC/SilentPatchVC.cpp#L2534)
					if (IsReadablePointer((void*)0x601740) && *((DWORD*)(0x601740)) == 0x3EEC0D8B)
					{
						logc(FOREGROUND_CYAN, "Patching Mouse Fix at 0x601740 - Currently: %08X\n", *((DWORD*)(0x601740)));
						WriteProtectedDWORD(0x601740, 0xC3C030);
					}
					if (IsReadablePointer((void*)0x601770) && *((DWORD*)(0x601770)) == 0x3EEC0D8B)
					{
						logc(FOREGROUND_CYAN, "Patching Mouse Fix at 0x601770 - Currently: %08X\n", *((DWORD*)(0x601770)));
						WriteProtectedDWORD(0x601770, 0xC3C030);
					}

					ApplyPatches();

					RestrictProcessors(config.GetInt("CPUCount", -1));
					SecuROMPatchingDone = true;
				}
				else
				{
					logc(FOREGROUND_RED, "Failed to find second CD Check patch location\n");
				}
			}
			else
			{
				logc(FOREGROUND_RED, "Failed to find CD Check patch location\n");
				logc(FOREGROUND_LIME, "Checking to see Sid Meier's Pirates style protection is present\n");
				
				std::vector<DWORD> GeometryPiratesCDPatches;
				for (auto& section : sections)
				{
					CDCheckSectionStart = ExeAddr + section->VirtualAddress;
					CDCheckSectionEnd = ExeAddr + section->VirtualAddress + section->Misc.VirtualSize;
					GeometryPiratesCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "032424DD1D????????", "Pirates! Geometry Check");
					if (GeometryPiratesCDPatches.size() == 2)
						break;
				}

				if (GeometryPiratesCDPatches.size() == 2)
				{
					logc(FOREGROUND_GREEN, "Found Pirates! Style Geometry Check. Removing CRCs\n");

					CRCFixer(CDCheckSectionStart, CDCheckSectionEnd, true, false);
										
					// Find CD Check 1
					FirstCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "2B05????????5868????????75", "CD CHECK 1");
					for (DWORD addr : FirstCDPatches)
					{
						logc(FOREGROUND_GREEN, "Found CD Check 1 patch location at %08X\n", addr);
						WritePatchBYTE(addr + 0xC, 0x90);
						WritePatchBYTE(addr + 0xD, 0x90);
					}
					
					// Find CD Check 3 (2 is taken care of by the PVD we send back)
					auto ThirdCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "A1????????2BC15868????????74", "CD CHECK 3");
					for (DWORD addr : ThirdCDPatches)
					{
						logc(FOREGROUND_GREEN, "Found CD Check 3 patch location at %08X\n", addr);
						WritePatchBYTE(addr + 0xD, 0xEB);
					}

					// Find CD Check 4
					auto FourthCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "2B3C85????????5F", "CD CHECK 4");
					for (DWORD addr : FourthCDPatches)
					{
						logc(FOREGROUND_GREEN, "Found CD Check 4 patch location at %08X\n", addr);
						WritePatchBYTE(addr, 0x38);			// cmp al, al
						WritePatchBYTE(addr + 1, 0xC0);
						WritePatchBYTE(addr + 2, 0x90);
						WritePatchDWORD(addr + 3, 0x90909090);
					}

					logc(FOREGROUND_GREEN, "Geometry patch hook...\n");
					for (DWORD addr : GeometryPiratesCDPatches)
					{
						WritePatchBYTE(addr + 3, 0x90);
						WritePatchBYTE(addr + 4, 0xE8);
						WritePatchDWORD(addr + 5, (((DWORD)(GeometryHookForSecuROM45)) - (addr + 4)) - 5);
					}

					ApplyPatches();

					logc(FOREGROUND_GREEN, "Pirates! Style Protection Patching Complete\n");
					
					RestrictProcessors(config.GetInt("CPUCount", -1));
					SecuROMPatchingDone = true;
				}
				else
				{
					logc(FOREGROUND_RED, "Failed to even the find Pirates Geometry CD Check patch location! Trying Securom3 (early Securom 4)\n");
					SecuROMPatchingDone = SecuROM345Patching();
					GetKey(true);
				}
			}
		}
		else
		{
			if (VersionMajor == 3)
			{
				SecuROMPatchingDone = SecuROM345Patching();
			}
			else
			{
				logc(FOREGROUND_RED, "Unsupported SecuROM version for patching\n");
				GetKey(true);
			}
		}
	}
	else
	{
		logc(FOREGROUND_RED, "Failed to find SecuROM version string\n");
	}

	return SecuROMPatchingDone;
}