#pragma once
#include <string>
#include <math.h>
#include <list>

using namespace std;

struct LRPair {
	string L;
	string R;
	string cipherTextBits;
};

class SDES {
private:
	string L = "";
	string R = "";
	string R1 = "";
	string R2 = "";
	string concatedBits = "";
	string cipherTextBits = "";
	string plainTextBits = "";
	string keyBits = "";
	string ithKey = "";
	int ciphertext = 0;
	int plainText;
	int key;
	list<string> k;
	list<LRPair> LR;
	

public:
	SDES(int &, int&);
	~SDES();
	
	void convertToBinaryWithShift(int);
	void convertToBinary(int, int);
	void setL(char &);
	void setR(char &);
	void setR(string &);
	void setR1(char &);
	void setR2(char &);
	void setList(string,string);
	void setCipherTextBits(string);
	void setCipherText(int);
	void setPlainTextBits(int);
	void setPlainTextBits(string);
	void setIthKeyBits(int);
	void setKeyBits(int);
	void setKeyBits(string);
	void halfBits(string &, int);
	void insertZeros(int);
	void print();
	void generateK(string &);
	void rotateBits(int &);
	void expandBits(string &);
	void xorStrings(string &, string&, int);
	void rkFunction(string *, string *, string[][8], string[][8]);

	int binaryToDecimal(string &);
	int getPlainText();
	int getCipherText();
	int getKey();
	
	
	list<LRPair>& getLRList();
	list<string>& getKeyList();

	string &getL();
	string &getR();
	string *getR1();
	string *getR2();
	string &getPlainTextBits();
	string &getKeyBits();
	string &getIthKeyBits();
	string &getConcatedBits();
	string &getCipherTextBits();	
	string getSboxValue(int*, int*, string[][8]);
};
