/* GPLv2 (c) Airbus */
OUTPUT_FORMAT("elf32-i386","elf32-i386","elf32-i386");
OUTPUT_ARCH("i386")

ENTRY(entry)

PHDRS
{
   phboot  PT_LOAD FLAGS (7);
   phstack PT_LOAD FLAGS (6);
   phsetup PT_LOAD FLAGS (7);
}

SECTIONS
{
   . = 0x300000;
   .mbh      : { KEEP(*(.mbh)) . = ALIGN(4);     } : phboot
   .stack    : { KEEP(*(.stack))                 } : phstack

   __kernel_start__ = .;

   .idt_jmp  : { KEEP(*(.idt_jmp))               } : phsetup
   .text     : { *(.text)                        } : phsetup
   .rodata   : { *(.rodata)                      } : phsetup
   .data     : { *(.data)                        } : phsetup
   .bss      : { *(.bss COMMON)                  } : phsetup
   /DISCARD/ : { *(.note* .indent .comment)      } : phsetup

   . = 0x500000;           /* adresse où placer la section GDT */
   .my_gdt_section : {
        KEEP(*(.my_gdt_section))
    }

   /* AJOUT POUR L'EXAMEN : Alignement du code utilisateur à 8MB */
   . = 0x800000;
   .user : {
        KEEP(*(.user))
   }

   __kernel_end__ = .;
}
