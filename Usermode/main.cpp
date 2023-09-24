
#define UMDF_USING_NTSTATUS
#include <Windows.h>
#include <ntstatus.h>
#include <strsafe.h>
#include <stdio.h>

#include "driver.h"

int main(int argc, char** argv)
{
	CsmDriver driver;

	if ( driver.LoadDriver() ) {
		printf("[+] Driver Loaded.\n");

		printf("[+] Driver Calculation of 5 + 10 = %d.\n", driver.CalculateForMe(5, 10));
		printf("[+] Show me my process address: %llX.", driver.GetMyProcess());

		driver.UnloadDriver();
		return 0;
	}

	return -1;
}