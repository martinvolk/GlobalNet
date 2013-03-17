#include <iostream>
#include <memory.h>
#include <stdlib.h>
#include <map>

using namespace std;

// Custom new operator. Do your memory logging here.
void* operator new (size_t size)
{
    void* x = malloc(size);
    //cout << "Allocated " << size << " byte(s) at address " << x << endl;
    return x;  
}

// You must override the default delete operator to detect all deallocations
void operator delete (void* p)
{
   free(p);
   //cout << "Freed memory at address " << p << endl;
}

// You also should provide an overload with the same arguments as your
// placement new. This would be called in case the constructor of the 
// created object would throw.
void operator delete (void* p, char* file, unsigned int line)
{
   free(p);
   cout << "Freed memory at address " << p << endl;
}


