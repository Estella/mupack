#include "patternfind.h"
#include <stdio.h>
#include <ctype.h>
#include <vector>

struct PATTERNNIBBLE
{
    unsigned char n;
    bool all;
};

struct PATTERNBYTE
{
    PATTERNNIBBLE n[2];
};

static int formathexpattern(char* string)
{
    int len=strlen(string);
    _strupr(string);
    char* new_string=(char*)malloc(len+1);
    memset(new_string, 0, len+1);
    for(int i=0,j=0; i<len; i++)
        if(string[i]=='?' || isxdigit(string[i]))
            j+=sprintf(new_string+j, "%c", string[i]);
    strcpy(string, new_string);
    free(new_string);
    return strlen(string);
}

static bool patterntransform(const char* text, std::vector<PATTERNBYTE>* pattern)
{
    if(!text || !pattern)
        return false;
    pattern->clear();
    int len=strlen(text);
    if(!len)
        return false;
    char* newtext=(char*)malloc(len+2);
    strcpy(newtext, text);
    len=formathexpattern(newtext);
    if(len%2) //not a multiple of 2
    {
        newtext[len]='?';
        newtext[len+1]='\0';
        len++;
    }
    PATTERNBYTE newByte;
    for(int i=0,j=0; i<len; i++)
    {
        if(newtext[i]=='?') //wildcard
        {
            newByte.n[j].all=true; //match anything
            newByte.n[j].n=0;
            j++;
        }
        else //hex
        {
            char x[2]="";
            *x=newtext[i];
            unsigned int val=0;
            sscanf(x, "%x", &val);
            newByte.n[j].all=false;
            newByte.n[j].n=val&0xF;
            j++;
        }

        if(j==2) //two nibbles = one byte
        {
            j=0;
            pattern->push_back(newByte);
        }
    }
    free(newtext);
    return true;
}

static bool patternmatchbyte(unsigned char byte, PATTERNBYTE* pbyte)
{
    unsigned char n1=(byte>>4)&0xF;
    unsigned char n2=byte&0xF;
    int matched=0;
    if(pbyte->n[0].all)
        matched++;
    else if(pbyte->n[0].n==n1)
        matched++;
    if(pbyte->n[1].all)
        matched++;
    else if(pbyte->n[1].n==n2)
        matched++;
    return (matched==2);
}

size_t patternfind(unsigned char* data, size_t size, const char* pattern)
{
    std::vector<PATTERNBYTE> searchpattern;
    if(!patterntransform(pattern, &searchpattern))
        return -1;
    size_t searchpatternsize=searchpattern.size();
    for(size_t i=0,pos=0; i<size; i++) //search for the pattern
    {
        if(patternmatchbyte(data[i], &searchpattern.at(pos))) //check if our pattern matches the current byte
        {
            pos++;
            if(pos==searchpatternsize) //everything matched
                return i-searchpatternsize+1;
        }
        else
            pos=0; //reset current pattern position
    }
    return -1;
}

static void patternwritebyte(unsigned char* byte, PATTERNBYTE* pbyte)
{
    unsigned char n1=(*byte>>4)&0xF;
    unsigned char n2=*byte&0xF;
    if(!pbyte->n[0].all)
        n1=pbyte->n[0].n;
    if(!pbyte->n[1].all)
        n2=pbyte->n[1].n;
    *byte=((n1<<4)&0xF0)|(n2&0xF);
}

void patternwrite(unsigned char* data, size_t size, const char* pattern)
{
    std::vector<PATTERNBYTE> writepattern;
    if(!patterntransform(pattern, &writepattern))
        return;
    size_t writepatternsize=writepattern.size();
    if(writepatternsize>size)
        writepatternsize=size;
    for(size_t i=0; i<writepatternsize; i++)
        patternwritebyte(&data[i], &writepattern.at(i));
}

bool patternsnr(unsigned char* data, size_t size, const char* searchpattern, const char* replacepattern)
{
    size_t found=patternfind(data, size, searchpattern);
    if(found==-1)
        return false;
    patternwrite(data+found, size-found, replacepattern);
    return true;
}
