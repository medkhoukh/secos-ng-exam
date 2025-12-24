/* GPLv2 (c) Airbus */
#include <debug.h>
#include <segmem.h>
#include <string.h>
#include <intr.h>
#include <pagemem.h>
#include <io.h>
#include <pic.h>

/* --- CONFIGURATION & MACROS --- */

#define c0_idx  1
#define d0_idx  2
#define c3_idx  3
#define d3_idx  4
#define ts_idx  5

#define c0_sel  gdt_krn_seg_sel(c0_idx)
#define d0_sel  gdt_krn_seg_sel(d0_idx)
#define c3_sel  gdt_usr_seg_sel(c3_idx)
#define d3_sel  gdt_usr_seg_sel(d3_idx)
#define ts_sel  gdt_krn_seg_sel(ts_idx)

#define VADDR_SHARED_T1 0x40000000 
#define VADDR_SHARED_T2 0x80000000 

/* --- HELPER FUNCTIONS --- */

extern uint32_t __kernel_end__;

static inline void set_cr3(uint32_t cr3) {
    asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
}

static inline void enable_paging() {
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

void pic_enable_irq(int irq) {
    uint8_t mask;
    uint16_t port;
    if (irq < 8) {
        port = PIC_IMR(PIC1);
        mask = inb(port);
        outb(mask & ~(1 << irq), port);
    } else {
        port = PIC_IMR(PIC2);
        mask = inb(port);
        outb(mask & ~(1 << (irq - 8)), port);
    }
}

/* --- STRUCTURES & GLOBALES --- */

typedef struct {
    uint32_t kstack_top;
    uint32_t esp;
    uint32_t cr3;
} task_t;

/* Section GDT spécifique pour éviter l'écrasement */
seg_desc_t GDT[6] __attribute__((section(".my_gdt_section"))); 
tss_t      TSS;

static uint32_t free_mem_addr;
task_t tasks[2];
int current_task_id = 0;

/* Prototypes alignés à 8MB via linker script */
void __attribute__((section(".user"))) user1();
void __attribute__((section(".user"))) user2();

/* --- SETUP GDT --- */

#define gdt_flat_dsc(_dSc_,_pVl_,_tYp_)                                 \
   ({                                                                   \
      (_dSc_)->raw     = 0;                                             \
      (_dSc_)->limit_1 = 0xffff;                                        \
      (_dSc_)->limit_2 = 0xf;                                           \
      (_dSc_)->type    = _tYp_;                                         \
      (_dSc_)->dpl     = _pVl_;                                         \
      (_dSc_)->d       = 1;                                             \
      (_dSc_)->g       = 1;                                             \
      (_dSc_)->s       = 1;                                             \
      (_dSc_)->p       = 1;                                             \
   })

#define tss_dsc(_dSc_,_tSs_)                                            \
   ({                                                                   \
      raw32_t addr    = {.raw = _tSs_};                                 \
      (_dSc_)->raw    = sizeof(tss_t);                                  \
      (_dSc_)->base_1 = addr.wlow;                                      \
      (_dSc_)->base_2 = addr._whigh.blow;                               \
      (_dSc_)->base_3 = addr._whigh.bhigh;                              \
      (_dSc_)->type   = SEG_DESC_SYS_TSS_AVL_32;                        \
      (_dSc_)->p      = 1;                                              \
   })

#define c0_dsc(_d) gdt_flat_dsc(_d,0,SEG_DESC_CODE_XR)
#define d0_dsc(_d) gdt_flat_dsc(_d,0,SEG_DESC_DATA_RW)
#define c3_dsc(_d) gdt_flat_dsc(_d,3,SEG_DESC_CODE_XR)
#define d3_dsc(_d) gdt_flat_dsc(_d,3,SEG_DESC_DATA_RW)

void init_gdt() {
   gdt_reg_t gdtr;
   GDT[0].raw = 0ULL;
   c0_dsc( &GDT[c0_idx] );
   d0_dsc( &GDT[d0_idx] );
   c3_dsc( &GDT[c3_idx] );
   d3_dsc( &GDT[d3_idx] );

   gdtr.desc  = GDT;
   gdtr.limit = sizeof(GDT) - 1;
   set_gdtr(gdtr);

   set_cs(c0_sel);
   set_ss(d0_sel);
   set_ds(d0_sel);
   set_es(d0_sel);
   set_fs(d0_sel);
   set_gs(d0_sel);

   tss_dsc(&GDT[ts_idx], (offset_t)&TSS);
   set_tr(ts_sel);
}

/* --- GESTION MEMOIRE --- */

void* palloc_page() {
    void* page = (void*)free_mem_addr;
    _memset32(page, 0, PAGE_SIZE);
    free_mem_addr += PAGE_SIZE;
    return page;
}

void map_page(pde32_t* pgd, uint32_t vaddr, uint32_t paddr, uint32_t flags) {
    uint32_t pde_idx = pd32_get_idx(vaddr);
    uint32_t pte_idx = pt32_get_idx(vaddr);
    pte32_t* ptb;

    if (!pg_present(&pgd[pde_idx])) {
        ptb = (pte32_t*)palloc_page();
        pg_set_entry(&pgd[pde_idx], PG_USR|PG_RW, page_get_nr(ptb));
    } else {
        ptb = (pte32_t*)page_get_addr(pgd[pde_idx].addr);
    }
    pg_set_entry(&ptb[pte_idx], flags, page_get_nr(paddr));
}

/* --- ORDONNANCEUR --- */

uint32_t __regparm__(1) schedule(int_ctx_t *ctx) {
    tasks[current_task_id].esp = (uint32_t)ctx;
    current_task_id = (current_task_id + 1) % 2;

    TSS.s0.esp = tasks[current_task_id].kstack_top;
    set_cr3(tasks[current_task_id].cr3);
    pic_eoi(PIC1);

    return tasks[current_task_id].esp;
}

void __attribute__((naked)) irq0_isr() {
    asm volatile (
        "pusha              \n"
        "mov %esp, %eax     \n"
        "call schedule      \n"
        "mov %eax, %esp     \n"
        "popa               \n"
        "iret"
    );
}

/* --- SYSCALL --- */

/* CORRECTION: Utilisation de l'interruption 0x80 (128) */
void sys_counter(uint32_t *counter) {
    asm volatile ("int $0x80"::"S"(counter));
}

void __regparm__(1) syscall_handler(int_ctx_t *ctx) {
    uint32_t *user_ptr = (uint32_t *)ctx->gpr.esi.raw;
    debug("Tache 2 (lecture partagée) : %d\n", *user_ptr);
}

void syscall_isr() {
   asm volatile (
      "leave ; pusha        \n"
      "mov %esp, %eax       \n"
      "call syscall_handler \n"
      "popa ; iret"
      );
}

/* --- TACHES UTILISATEUR --- */

void __attribute__((section(".user"))) user1() {
    uint32_t *shared = (uint32_t*)VADDR_SHARED_T1;
    *shared = 0;
    while(1) {
        (*shared)++;
        for(int i=0; i<500000; i++) asm volatile("nop");
    }
}

void __attribute__((section(".user"))) user2() {
    uint32_t *shared = (uint32_t*)VADDR_SHARED_T2;
    while(1) {
        sys_counter(shared);
        for(int i=0; i<2000000; i++) asm volatile("nop");
    }
}

/* --- INITIALISATION --- */

void setup_task(int id, void (*func)(), uint32_t shared_phy_page, uint32_t vaddr_shared) {
    pde32_t* pgd = (pde32_t*)palloc_page();
    tasks[id].cr3 = (uint32_t)pgd;

    /* Identity Map complet (Kernel + User code) */
    uint32_t max_addr = (uint32_t)&__kernel_end__ + 0x100000;
    for (uint32_t addr = 0; addr < max_addr; addr += PAGE_SIZE) {
        map_page(pgd, addr, addr, PG_USR|PG_RW);
    }

    /* Map Shared Memory */
    map_page(pgd, vaddr_shared, shared_phy_page, PG_USR|PG_RW);

    /* Stacks */
    uint32_t kstack_base = (uint32_t)palloc_page();
    tasks[id].kstack_top = kstack_base + PAGE_SIZE;

    uint32_t ustack_base = (uint32_t)palloc_page();
    uint32_t ustack_top  = ustack_base + PAGE_SIZE;
    map_page(pgd, ustack_base, ustack_base, PG_USR|PG_RW);

    /* Context */
    uint32_t *stack = (uint32_t*)tasks[id].kstack_top;
    *(--stack) = d3_sel;          
    *(--stack) = ustack_top;      
    *(--stack) = 0x200;           
    *(--stack) = c3_sel;          
    *(--stack) = (uint32_t)func;  
    
    for(int i=0; i<8; i++) *(--stack) = 0;

    tasks[id].esp = (uint32_t)stack;
}

void tp() {
    free_mem_addr = (uint32_t)&__kernel_end__;
    if(free_mem_addr & (PAGE_SIZE-1))
        free_mem_addr = (free_mem_addr & ~(PAGE_SIZE-1)) + PAGE_SIZE;

    init_gdt();

    idt_reg_t idtr;
    get_idtr(idtr);

    /* Installation Timer (IRQ0) */
    build_int_desc(&idtr.desc[0x20], 0x08, (uint32_t)irq0_isr);
    
    /* CORRECTION: Installation Syscall à l'index 0x80 (128) */
    build_int_desc(&idtr.desc[0x80], 0x08, (uint32_t)syscall_isr);
    idtr.desc[0x80].dpl = 3; 

    pic_enable_irq(0); 

    uint32_t shared_phy = (uint32_t)palloc_page();
    setup_task(0, user1, shared_phy, VADDR_SHARED_T1);
    setup_task(1, user2, shared_phy, VADDR_SHARED_T2);

    current_task_id = 0;
    set_cr3(tasks[0].cr3);
    enable_paging();

    TSS.s0.esp = tasks[0].kstack_top;
    TSS.s0.ss  = d0_sel;

    asm volatile (
        "mov %0, %%esp \n"
        "popa          \n"
        "iret          \n"
        : : "r"(tasks[0].esp)
    );

    while(1);
}