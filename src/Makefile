patcher_root: patcher.cpp
	g++ -o patcher_root patcher.cpp
	`

runme_user:	Pixsys.cu
	/usr/local/cuda/bin/nvcc -ccbin g++ -I../../common/inc -m64 -gencode arch=compute_20,code=sm_20 -gencode arch=compute_20,code=sm_21 -gencode arch=compute_30,code=sm_30 -gencode arch=compute_32,code=sm_32 -gencode arch=compute_35,code=sm_35 Pixsys.cu -o runme_user

