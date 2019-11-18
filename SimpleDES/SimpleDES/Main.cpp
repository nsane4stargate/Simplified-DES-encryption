/******************************************************************************************
 * Problem 7 : Defines the entry point for the console application.						  *
 *																						  *
 * Author: Lea Middleton                                                                  *
 *																						  *
 * Date: 2.14.2019																		  *
 ******************************************************************************************/

#include "SDES.h"
#include <iostream>
#include <iterator>
#include <list>
#include <algorithm>
#include <string>

using namespace std;

int main() {
	
	int plaintext;
	int key;

	/* Hard coded S_Boxes*/
	string S1[2][8] = { { "101", "010", "001", "110", "011", "100", "111", "000" },
						{ "001", "100", "110", "010", "000", "111", "101", "011"} };
	string S2[2][8] = { { "100", "000", "110", "101", "111", "001", "011", "010" },
						{ "101", "011", "000", "111", "110", "010", "001", "100"} };

	/* Get user input for plaintext */
	printf("Enter plaintext as an integer: ");
	cin >> plaintext;
	while (cin.fail() || plaintext < 0 || plaintext > 4095){
		if (cin.fail()) {
			printf("\n");
			printf("Must input an integer!! \n");
		}
		if (plaintext < 0 || plaintext > 4095) {
			printf("Must input an integer between 0 and 4095!! \n");
		}
		cin.clear();
		cin.ignore(256, '\n');
		printf("Enter re-enter plaintext as an integer: ");
		cin >> plaintext;
		printf("\n");
	}

	/* Get user input for key*/
	printf("Enter the key as an integer: ");
	cin >> key;
	while (cin.fail() || key < 0 || key > 511) {

		if (cin.fail()) {
			printf("Must input an integer!! \n ");
		}
		if (key < 0 || key> 511) {
			printf("Must input an integer between 0 and 511!! ");
			printf("\n");
		}
		cin.clear();
		cin.ignore(256, '\n');
		printf("Enter re-enter the key as an integer: ");
		cin >> key;
		printf("\n");
	}
	
	/* Create a SDES object */
	SDES code(plaintext, key);

	/* Convert integer plaintext into binary */
	if (plaintext == 0) {
		code.insertZeros(1);
	}
	else {
		code.convertToBinary(code.getPlainText(),1);
		code.insertZeros(1);
	}

	/* Convert integer key into binary */
	if (key == 0) {
		code.insertZeros(2);
	}
	else {
		code.convertToBinary(code.getKey(),2);
		code.insertZeros(2);
	}

	/* Half the plaintext bits with
	   int 1 to activate 1st option */
	code.halfBits(code.getPlainTextBits(), 1);

	/* Keep track of L and R after Split */
	LRPair pair; pair.L = code.getL(); pair.R = code.getR();
	string currentR = code.getR(), previousR = "";

	/* Initialize the list of L and R the
	   results before the 1st round */
	if (code.getLRList().empty()) {
		code.getLRList().push_front(pair);
	}

	/* Generate k_ith bits */
	code.generateK(code.getKeyBits());

	/* Loop for generating the CipherText */
	int numOfRounds = 5, currentRound = 1;
	list<string>::iterator it = code.getKeyList().begin();

	while (currentRound < numOfRounds) {
		if (previousR.length() > 0) {
			previousR.clear();
			previousR += currentR;
		}
		if (currentRound > 1) {
			/* Half the next round of plaintext that is 
			   concatedBits from the previous round. Use
			   int 1 to activate 1st option */
			code.halfBits(code.getCipherTextBits(), 1);
		}
		code.expandBits(code.getR());
		if (it != code.getKeyList().end()) {
			string currentIthKey = *it;
			code.xorStrings(code.getR(), currentIthKey, 1);
			it++;
		}
		code.rkFunction(code.getR1(), code.getR2(), S1, S2);
		code.xorStrings(code.getR(), code.getL(), 0);
		previousR = currentR;

		/* Update L */
		code.getL().clear();
		code.getL().append(previousR);
		currentR.clear();
		currentR = code.getR();

		/* Clear current PlainTextBit and update it with
		   L and R values concate in that order */
		if (code.getCipherTextBits().length() > 0) {
			code.getCipherTextBits().clear();
		}
		code.getCipherTextBits().append(code.getL());
		code.getCipherTextBits().append(code.getR());

		/* Add current round updated L and R to the list
		   of LRList */
		pair.L = previousR; pair.R = currentR; pair.cipherTextBits = code.getCipherTextBits();
		code.getLRList().push_back(pair);

		currentRound++;
	}

	code.print();

	char quit;
	cin >> quit;
}