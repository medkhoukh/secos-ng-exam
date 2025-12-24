/* GPLv2 (c) Airbus */
#include <debug.h>
#include <segmem.h>
#include <string.h>

#define gdt_len 6
#define addr_limit_1 0xFFFFFFFF
#define addr_base_1 0x00000000
#define addr_base_2 0x600000
#define addr_gdtr 0x500000 //alignée sur 8 octets


seg_desc_t gdt_table[gdt_len] __attribute__((section(".my_gdt_section")));


void userland() {
   asm volatile ("mov %eax, %cr0");
}

void configure_segment_descriptor(int indice, int type, int addr_base, int addr_limit, int granularite) {
    gdt_table[indice].limit_1 = (addr_limit) & 0xFFFF;  // Limite basse (16 bits)
    gdt_table[indice].base_1  = (addr_base) & 0xFFFF;
    gdt_table[indice].base_2  = (addr_base >> 16) & 0xFF;
    gdt_table[indice].type    = type;       // Code segment, execute/read
    gdt_table[indice].s       = 1;        // System descriptor (1 = code/data, 0 = system)
    gdt_table[indice].dpl     = 0;        // Privilege level 0 (kernel)
    gdt_table[indice].p       = 1;        
    gdt_table[indice].limit_2 = (addr_limit >> 16) & 0xF ;      // Limite haute (4 bits) - complète à 0xFFFFF
    gdt_table[indice].avl     = 0;        // Available bit (non utilisé)
    gdt_table[indice].l       = 0;        // Long mode bit (0 = 32-bit)
    gdt_table[indice].d       = 1;        // Default operation size (1 = 32-bit)
    gdt_table[indice].g       = granularite;        // Granularity (1 = 4KB pages , 0 = octet par octet de granularité)
    gdt_table[indice].base_3  = (addr_base >> 24) & 0xFF;
}

void print_gdt_content(gdt_reg_t gdtr_ptr) {
    seg_desc_t* gdt_ptr;
    gdt_ptr = (seg_desc_t*)(gdtr_ptr.addr);
    int i=0;
    while ((uint32_t)gdt_ptr < ((gdtr_ptr.addr) + gdtr_ptr.limit)) {
        uint32_t start = gdt_ptr->base_3<<24 | gdt_ptr->base_2<<16 | gdt_ptr->base_1;
        uint32_t end;
        if (gdt_ptr->g) {
            end = start + ( (gdt_ptr->limit_2<<16 | gdt_ptr->limit_1) <<12) + 4095;
        } else {
            end = start + (gdt_ptr->limit_2<<16 | gdt_ptr->limit_1);
        }
        debug("%d ", i);
        debug("[0x%x ", start);
        debug("- 0x%x] ", end);
        debug("seg_t: 0x%x ", gdt_ptr->type);
        debug("desc_t: %d ", gdt_ptr->s);
        debug("priv: %d ", gdt_ptr->dpl);
        debug("present: %d ", gdt_ptr->p);
        debug("avl: %d ", gdt_ptr->avl);
        debug("longmode: %d ", gdt_ptr->l);
        debug("default: %d ", gdt_ptr->d);
        debug("gran: %d ", gdt_ptr->g);
        debug("\n");
        gdt_ptr++;
        i++;
    }
}


void tp() {
    gdt_reg_t gdtr_ptr;
    get_gdtr(gdtr_ptr);
    printf("pointeur vers gdt : 0x%08lx \n",  gdtr_ptr.addr);
    printf("selecteurs de segments \n");
    
    uint16_t cs = get_seg_sel(cs);
    printf(" cs : 0x%x \n ", cs );

    uint16_t ss = get_ss();
    printf(" ss : 0x%x \n ", ss );

    uint16_t ds = get_ds();
    printf(" ds : 0x%x \n ", ds );

    uint16_t es = get_es();
    printf(" es : 0x%x \n ", es );

    uint16_t fs = get_fs();
    printf(" fs : 0x%x \n ", fs );
    
    uint16_t gs = get_gs();
    printf(" gs : 0x%x \n ", gs );
    print_gdt_content(gdtr_ptr);


    //configuration d'une nouvelle gdt
    
    gdt_table[0].raw = 0ULL;
    printf("adresse de la gdt : 0x%x \n" , (unsigned int) gdt_table);

    //cs
    configure_segment_descriptor(1,11, addr_base_1, addr_limit_1, 1);
    //ds
    configure_segment_descriptor(2,3, addr_base_1, addr_limit_1, 1);

    //"ajout d'un nouveau segment es de 32 octets , es
    configure_segment_descriptor(3,3, addr_base_2, addr_base_2 + 32 - 1, 0);

    // Configuration du nouveau GDT register
    gdt_reg_t new_gdtr;
    new_gdtr.limit = (gdt_len * sizeof(seg_desc_t)) - 1;  // Taille - 1 selon la definition
    new_gdtr.addr =(offset_t) gdt_table;  // Adresse de notre GDT , il faut mettre (offset ) pour lui dire quel type d'union on choisit
    set_gdtr(new_gdtr);

    set_es(gdt_krn_seg_sel(3));
    set_ds(gdt_krn_seg_sel(2));
    set_cs(gdt_krn_seg_sel(1));


    get_gdtr(gdtr_ptr);
    print_gdt_content(gdtr_ptr);


    
    printf("cs : 0x%x \n ", get_seg_sel(cs) );

    printf("ds : 0x%x \n ", get_ds() );

    printf("es : 0x%x \n ", get_es() );

    //Q10
    printf("utilisation du registre es \n");


    char  src[64];
    char *dst = 0;

    
    memset(src, 0xff, 64);
    // rien ne se passe car on dépasse pas la limite du segment
    _memcpy8(dst, src, 32);

    // faute , handler #13 qui gère les exception générale
    _memcpy8(dst, src, 100);

        // Q12
    gdt_table[4].limit_1 = 0xffff;   //:16;     /* bits 00-15 of the segment limit */
    gdt_table[4].base_1 = 0x0000;    //:16;     /* bits 00-15 of the base address */
    gdt_table[4].base_2 = 0x00;      //:8;      /* bits 16-23 of the base address */
    gdt_table[4].type = 11;//Code,RX //:4;      /* segment type */
    gdt_table[4].s = 1;              //:1;      /* descriptor type */
    gdt_table[4].dpl = 3; //ring3    //:2;      /* descriptor privilege level */
    gdt_table[4].p = 1;              //:1;      /* segment present flag */
    gdt_table[4].limit_2 = 0xf;      //:4;      /* bits 16-19 of the segment limit */
    gdt_table[4].avl = 1;            //:1;      /* available for fun and profit */
    gdt_table[4].l = 0; //32bits     //:1;      /* longmode */
    gdt_table[4].d = 1;              //:1;      /* default length, depend on seg type */
    gdt_table[4].g = 1;              //:1;      /* granularity */
    gdt_table[4].base_3 = 0x00;      //:8;      /* bits 24-31 of the base address */
    gdt_table[5].limit_1 = 0xffff;   //:16;     /* bits 00-15 of the segment limit */
    gdt_table[5].base_1 = 0x0000;    //:16;     /* bits 00-15 of the base address */
    gdt_table[5].base_2 = 0x00;      //:8;      /* bits 16-23 of the base address */
    gdt_table[5].type = 3; //data,RW //:4;      /* segment type */
    gdt_table[5].s = 1;              //:1;      /* descriptor type */
    gdt_table[5].dpl = 3; //ring3    //:2;      /* descriptor privilege level */
    gdt_table[5].p = 1;              //:1;      /* segment present flag */
    gdt_table[5].limit_2 = 0xf;      //:4;      /* bits 16-19 of the segment limit */
    gdt_table[5].avl = 1;            //:1;      /* available for fun and profit */
    gdt_table[5].l = 0; // 32 bits   //:1;      /* longmode */
    gdt_table[5].d = 1;              //:1;      /* default length, depend on seg type */
    gdt_table[5].g = 1;              //:1;      /* granularity */
    gdt_table[5].base_3 = 0x00;      //:8;      /* bits 24-31 of the base address */
    // end Q12

    // Q13
    // DS/ES/FS/GS
    set_ds(gdt_usr_seg_sel(5));
    set_es(gdt_usr_seg_sel(5));
    set_fs(gdt_usr_seg_sel(5));
    set_gs(gdt_usr_seg_sel(5));
    // SS
    set_ss(gdt_usr_seg_sel(5));


}
