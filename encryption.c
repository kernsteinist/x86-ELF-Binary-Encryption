#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <elf.h>


struct info{

Elf32_Addr  old_entry; /* original entrypoint */
Elf32_Off   offset; /* last load segment old offset */
Elf32_Word  endofsegment; /* end of last load segment */
Elf32_Addr  rva; /* virtual address of last load segment */
Elf32_Addr  text_rva; /* virtual adress of text section */
int text_distance;  /* distance between start of text section and start of runtime code */
int ep_distance;   /* distance between original entry point and start  of runtime code */
int size;          /* size of text section */
char xor_key;     /* xor key */

};

struct info *inf;

void read_elf(Elf32_Ehdr *ELF,int fd){
  read(fd,ELF,sizeof(Elf32_Ehdr));
}

int xor_text(int fd,Elf32_Shdr *SHT[],Elf32_Ehdr *EHT){
 
  int i=0;
  int index=0;

  while(EHT->e_shnum > i){
  if(EHT->e_entry >= SHT[i]->sh_addr && EHT->e_entry < SHT[i]->sh_addr + SHT[i]->sh_size ){
    index=i;
    break;
  }
  i++;
  }
 
 inf->old_entry=EHT->e_entry;
 inf->text_rva=SHT[index]->sh_addr;
 inf->size=SHT[index]->sh_size;

 lseek(fd,SHT[index]->sh_offset,SEEK_SET);
 char *text_section=(char *)malloc(SHT[index]->sh_size);
 
 read(fd,text_section,SHT[index]->sh_size);
 i=0;

 while(i<SHT[index]->sh_size){
  *(text_section+i)=*(text_section+i) ^ 0x12;
  i++;
 }

inf->xor_key=0x12;

lseek(fd,SHT[index]->sh_offset,SEEK_SET);
write(fd,text_section,SHT[index]->sh_size);

 return index;
}


void read_pht_eht(Elf32_Ehdr *EHT,Elf32_Phdr *PHT[],Elf32_Shdr *SHT[],int fd){

int i=0;
lseek(fd,EHT->e_phoff,SEEK_SET);

while(EHT->e_phnum > i){
  read(fd,PHT[i],EHT->e_phentsize);
i++;
}

lseek(fd,EHT->e_shoff,SEEK_SET);
i=0;

while(EHT->e_shnum > i){
  read(fd,SHT[i],EHT->e_shentsize);
i++;
}

} 


void reconstruct_segments(int fd,int index,Elf32_Ehdr *EHT,Elf32_Phdr *PHT[],Elf32_Shdr *SHT[]){

int i=0;
int index2last=0;// last load segment index

while(EHT->e_phnum > i){

 if(PHT[i]->p_type==PT_LOAD && (PHT[i]->p_vaddr < SHT[index]-> sh_addr && PHT[i]->p_vaddr+PHT[i]->p_filesz > SHT[index]->sh_addr)){
  PHT[i]->p_flags=PF_X + PF_R + PF_W;

 i++;
 continue; 
} 

if(PHT[i]->p_type==PT_LOAD)
  index2last=i;

i++;
  
}


inf->offset = PHT[index2last]->p_offset;
inf->endofsegment = PHT[index2last]->p_offset+PHT[index2last]->p_filesz;
inf->rva=PHT[index2last]->p_vaddr;

/*
int difference=PHT[index2last]->p_memsz-PHT[index2last]->p_filesz;
PHT[index2last]->p_filesz=get_file_size(fd)-PHT[index2last]->p_offset;
PHT[index2last]->p_memsz=PHT[index2last]->p_filesz+difference;
*/

PHT[index2last]->p_flags=PF_X + PF_R + PF_W;
PHT[index2last]->p_filesz+=500;
PHT[index2last]->p_memsz+=500;

lseek(fd,EHT->e_phoff,SEEK_SET);
i=0;

while(EHT->e_phnum > i){
write(fd,PHT[i],EHT->e_phentsize);
i++;
}

}



Elf32_Addr inject_runtimecode(int fd,char *code){
 
int current_offset = inf->endofsegment + sizeof(struct info)+10; 
int current_rvaddr = inf->rva +(current_offset-inf->offset);     

inf->ep_distance=current_rvaddr-inf->old_entry+0x32;                
inf->text_distance=current_rvaddr-inf->text_rva+0x32;               

printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
printf("current_offset %x\n",current_offset);
printf("current_rva    %x\n",current_rvaddr);
printf("inf->old_entry %x\n",inf->old_entry);
printf("inf->offset %x\n",inf->offset);
printf("inf->endofsegment %x\n",inf->endofsegment);
printf("inf->rva %x\n",inf->rva);
printf("inf->text_rva %x\n",inf->text_rva);
printf("inf->text_distance %x\n",inf->text_distance);
printf("inf->ep_distance %x\n",inf->ep_distance);
printf("inf->size %x\n",inf->size);
printf("inf->xor_key %x\n",inf->xor_key);
printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");


lseek(fd,current_offset,SEEK_SET);    
write(fd,inf,sizeof(struct info)); // write info to start of runtimecode

lseek(fd,current_offset+sizeof(struct info)+5,SEEK_SET);
write(fd,code,70);

return current_rvaddr+sizeof(struct info)+5;

}


char *inject_code="\x60\x90\x90\x90\xe8\x2c\x00\x00\x00\x8b\x4d\xea\x89\xeb"
"\x2b\x5d\xe2\x8a\x13\x32\x55\xee\x88\x13\x49\x43\x83\xf9\x00\x0f"
"\x85\xee\xff\xff\xff\x8b\x4d\xe6\x83\xc1\x2c\xf7\xd9\x89\x4d\x28"
"\x61\x90\xe9\xef\xbe\xad\xde\x8b\x2c\x24\xc3";



/*

___INJECT__CODE__ :

0x0 :old_entry  
0x4 :offset  
0x8 :endofsegment 
0xc :rva          
0x10:text_rva 
0x14:text_distance
0x18:ep_distance
0x1c:size
0x20:xor_key
0x21:JUNK_BYTE
0x22:JUNK_BYTE
0x23:JUNK_BYTE
0x24:JUNK_BYTE
0x25:JUNK_BYTE    
0x26:pusha
0x27:nop
0x28:nop
0x29:nop
0x2a:call 0x2c
0x2f:mov ecx,DWORD PTR[ebp-0x16]
0x32:mov ebx,ebp
0x34:sub ebx,DWORD PTR[ebp-0x1e]
0x37:mov dl,BYTE PTR[ebx]
0x39:xor    dl,BYTE PTR [ebp-0x12]
0x3c:mov    BYTE PTR [ebx],dl 
0x3d:dec ecx
0x3e:inc ebx
0x3f:cmp cx,0x0
0x42:jnz -0x12
0x48:mov    ecx,DWORD PTR [ebp-0x1a]
0x4b:add    ecx,0x2c
0x4f:neg ecx
0x51:mov DWORD PTR [ebp+0x28],ecx
0x54:popa
0x55:nop
0x56:jmp 0xdeadbeef
0x5b:mov ebp,[esp]
0x5e:ret
0x5f:nop

_________________________________________________________________________

*/

int main(int argc,char **argv){


Elf32_Ehdr *EHT;
int fd;
int i=0;


EHT=(Elf32_Ehdr *)malloc(52); // Allocate for Elf Header
inf=malloc(sizeof(struct info)); 
 
  if(argc!=2){
  	printf("Usage:encrypter file.out ... ! \n");
  	exit(2);
  }
    
 if( (fd=open(argv[1],O_RDWR)) == -1){
 	printf("error : open syscall \n ");
 	exit(2);
  }

 
read_elf(EHT,fd); // fill EHT.  

Elf32_Phdr *PHT[EHT->e_phnum];
Elf32_Shdr *SHT[EHT->e_shnum];

 
while(EHT->e_phnum > i){  // Allocate for Program Header Table
  PHT[i]=(Elf32_Phdr *)malloc(EHT->e_phentsize);
 i++;
 }

 i=0;

while(EHT->e_shnum > i){ // Allocate for Section Header Table
  SHT[i]=(Elf32_Shdr *)malloc(EHT->e_shentsize);
 i++;
 }


read_pht_eht(EHT,PHT,SHT,fd); // fill program header table and section header table.
int index=xor_text(fd,SHT,EHT);         // xor text section in file 
reconstruct_segments(fd,index,EHT,PHT,SHT);

Elf32_Addr new_ep=inject_runtimecode(fd,inject_code); 
EHT->e_entry=new_ep;

lseek(fd,0,SEEK_SET);
write(fd,EHT,sizeof(Elf32_Ehdr));


exit(0);

}
