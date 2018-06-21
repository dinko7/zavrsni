/*
Copyright 2018, Dinko Marinac

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// zavrsni.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

/* Program requires user to input password to log in. If the password is successfull the message "Succesfully logged in!" will be showed. 
   Correct password is ZAVRSNI{svaka_cast} and in the rest of comments is reffered as flag. The program takes users input and then makes ROT7(Ceasear's
   cipher with offset 7 and after that it does xor of every character with 0x55 to check if password is correct.
*/

//flag definition
vector<int> flag = {
	0x12, 0x1d, 0x16, 0xc, 0xf, 0x0, 0x5, 0x3d, 0x2f, 0x36, 0x3d, 0x27,
	0x3d, 0x33, 0x3f, 0x3d, 0x2f, 0x34, 0x3f
};

//takes user input and does xor with every byte and after that it checks if flag is entered
inline bool compute(string s)
{
	string result = "";
	for (int i = 0; i < s.size(); ++i)
	{
		result += s[i] ^ (char)(0x55);
	}

	if (result.size() != flag.size())
		return false;

	for (int i = 0; i < flag.size(); ++i)
	{
		if ((int)result[i] != flag[i])
			return false;
	}

	return true;
}

//calculate Ceasear's cipher
inline std::string rotEncrypt(const std::string& text, const int& s)
{
	std::string result = "";

	for (int i = 0; i < text.length(); i++)
	{
		if (isupper(text[i]))
			result += char(int(text[i] + s - 65) % 26 + 65);
		else
			result += char(int(text[i] + s - 97) % 26 + 97);
	}
	return result;
}

//login
inline void LoginRoutine()
{
	string input;
	cout << "Enter password to login: " << endl;
	cin >> input;

	TimeAttack(&DetectDebugger);

	//flag is ZAVRSNI{svaka_cast}
	if (compute(rotEncrypt(input, 7)))
	{
		cout << "Successfully logged in!" << endl;
	}
	else
	{
		cout << "Wrong password!" << endl;
	}

	system("pause");
}

//Undandled exception filter for anti-reversing pourpose
LONG WINAPI CustomUnhandledExceptionFilter(
	PEXCEPTION_POINTERS pExcepPointers)
{
	// Restore old UnhandledExceptionFilter
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)
		pExcepPointers->ContextRecord->Eax);

	// Skip the exception code
	pExcepPointers->ContextRecord->Eip += 2;

	return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
	SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);
	__asm {xor eax, eax}
	__asm {div eax} //division by zero will cause program to crash

	// Execution resumes here if there is no debugger
	HideThread(GetCurrentThread());
	if (DebugObjectCheck())
	{
		exit(0);
	}
	LoginRoutine();
	return 0;
}
