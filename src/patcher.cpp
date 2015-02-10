/**
 * Copyright 1993-2012 NVIDIA Corporation.  All rights reserved.
 *
 * Please refer to the NVIDIA end user license agreement (EULA) associated
 * with this source code for terms and conditions that govern your use of
 * this software. Any use, reproduction, disclosure, or distribution of
 * this software and related documentation outside the terms of the EULA
 * is strictly prohibited.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>



#define ALIGN 0x1000
using namespace std;

void *aligned_malloc(int size) {
    void *mem = malloc(size+ALIGN+sizeof(void*));
    void **ptr = (void**)((long)(mem+ALIGN+sizeof(void*)) & ~(ALIGN-1));
    ptr[-1] = mem;
    return ptr;
}

void aligned_free(void *ptr) {
    free(((void**)ptr)[-1]);
}



/**
 * Host function that prepares data array and passes it to the CUDA kernel.
 */
typedef struct hidden_driver_info
{
	long int start_addr;
	long int end_addr;
} hidden_driver_info ,*p_hidden_info;

typedef void (*s_funct) () ;
int main(void) {

	int pagesize = 0x1000;
	s_funct f;
	pagesize = getpagesize(); // get Page size of system (usually 0x1000)
	//printf("page size is: %d\n",pagesize);


	//Load kernel module:
	ifstream modules_fd("/proc/modules");
	string str;
	int addr_offset_from_nvidia = 35;
	unsigned long int base_nv_value, map_addr, lock_addr;
	string nvidia_base_addr;
	string m_lock_addr;
	string dma_map_addr;
	stringstream sstr;
    while (getline(modules_fd, str))
    {
		size_t pos = str.find("nvidia 1");
        if (pos != string::npos)
		{
			pos = str.find("0x");
			nvidia_base_addr = str.substr(pos+2);
			cout << "BASE ADDR IS: " << nvidia_base_addr << "\n";
			sstr << nvidia_base_addr;
			sstr >> hex >> base_nv_value;
			break;
		}
		// Process str
    }
	cout << "Base Nv addr hex is: " << hex << base_nv_value << "\n";
	map_addr = base_nv_value + 0x570bd0; //Known offset
	lock_addr = base_nv_value + 0x5770c0;
	sstr.str("");
	//cout << "S:" << map_addr << "\n";
	sstr << map_addr;
	dma_map_addr = sstr.str();
	sstr.str("");
	sstr << lock_addr;
	m_lock_addr = sstr.str();

	cout << "nv_dma_map_pages addr is: " << dma_map_addr << "\n os_lock_user_pages addr is :" << m_lock_addr << "\n";
	string CMD = "insmod hook.ko m_lock_addr=0x" + m_lock_addr + " dma_map_addr=0x" + dma_map_addr;
	cout << "CMD is: " << CMD << "\n";
	system(CMD.c_str());
	cout << "module installed, check it now via lsmod";
	return 0;
}
