/*
Copyright 2018, Dinko Marinac

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
	Header with anti-reversing utility functions which are used to obfuscate the code.
*/

#pragma once

#include <ctime>
#include <cstdlib>
#include "junkcode.h"

typedef unsigned long long int ullInt;
typedef long long int llInt;

/*
Wait is function which delays execution of a program for x miliseconds.
Anti-reverse friendly version of sleep function.
*/
inline void wait(const ullInt& mseconds)
{
	clock_t goal = mseconds + clock();
	while (goal > clock());
}

/*
Generates random number between 0x0 and 0x7fff seconds
*/
inline llInt getRandomTime()
{
	srand(time(nullptr) + 3357); //time + random prime number
	JUNK_CODE_2
	return rand() * 10000;
}
