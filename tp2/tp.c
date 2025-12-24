/* GPLv2 (c) Airbus */
#include <debug.h>
#include <intr.h>

void bp_handler() {
   uint32_t eip;
   asm volatile ("pusha");
   asm volatile ("mov 4(%%ebp), %0":"=r"(eip));
   debug("adresse eip : 0x%u \n" , eip);
   asm volatile ("popa");
   asm volatile ("leave ;iret");
}

void bp_trigger() {
	asm volatile ("int3");
	debug("after bp triggered\n");
}

void tp() {

	uint32_t addr_bp_handler = (uint32_t) bp_handler;
	// TODO print idtr
	idt_reg_t idt_register;
	get_idtr(idt_register);
	printf("pointeur vers idt : 0x%08lx \n",  idt_register.addr);

	int_desc_t *bp_desc = (int_desc_t *) (idt_register.addr + 3 * sizeof(int_desc_t));
	printf("pointeur vers bp intr : 0x%08lx \n", (long unsigned int )bp_desc); 

	bp_desc->offset_1 = (addr_bp_handler) & 0xFFFF;
	bp_desc->offset_2 = (addr_bp_handler >> 16 ) & 0xFFFF;  
	// TODO call bp_trigger
    bp_trigger();
}
