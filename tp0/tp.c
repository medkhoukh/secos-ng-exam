/* GPLv2 (c) Airbus */
#include <debug.h>
#include <info.h>

extern info_t   *info;
extern uint32_t __kernel_start__;
extern uint32_t __kernel_end__;

void tp() {
   debug("kernel mem [0x%p - 0x%p]\n", &__kernel_start__, &__kernel_end__);
   debug("MBI flags 0x%x\n", info->mbi->flags);

   multiboot_memory_map_t* entry = (multiboot_memory_map_t*)info->mbi->mmap_addr;
   while((uint32_t)entry < (info->mbi->mmap_addr + info->mbi->mmap_length)) {
      // TODO print "[start - end] type" for each entry
      printf(" [ 0x%08llx - 0x%08llx ]  %s \n" , entry->addr ,  entry->addr + entry->len - 1  , (entry->type == 1) ? "MULTIBOOT_MEMORY_AVAILABLE" : "MULTIBOOT_MEMORY_RESERVED" );
      entry++;
   }
   
   int *ptr_in_available_mem;
   ptr_in_available_mem = (int*)0x0;
   debug("Available mem (0x0): before: 0x%x ", *ptr_in_available_mem); // read
   *ptr_in_available_mem = 0xaaaaaaaa;                           // write
   debug("after: 0x%x\n", *ptr_in_available_mem);                // check

   int *ptr_in_reserved_mem;
   ptr_in_reserved_mem = (int*)0xf0000;
   debug("Reserved mem (at: 0xf0000):  before: 0x%x ", *ptr_in_reserved_mem); // read
   *ptr_in_reserved_mem = 0xaaaaaaaa;                           // write
   debug("after: 0x%x\n", *ptr_in_reserved_mem);                // check

   int *ptr_in_unavailable_mem;
   ptr_in_unavailable_mem = (int*)0xa0000000;
   debug("mémoire non dispo (at: 0xa0000000):  before: 0x%x ", *ptr_in_unavailable_mem); // read
   *ptr_in_unavailable_mem = 0xaaaaaaaa;                           // write
   debug("after: 0x%x\n", *ptr_in_unavailable_mem);                // check

}
