#include "SDES.h"

SDES::SDES(int &p, int &k): plainText(p), key(k){}

SDES::~SDES(){}


/*********************************
 *	     Void functions			 *
 *********************************/

void SDES::convertToBinaryWithShift(int num){
	if (num < 1) {
		return;
	}
	int quotient = num / 2;
	int remainder = num % 2;
	convertToBinaryWithShift(quotient);
	setIthKeyBits(remainder);
}

void SDES::convertToBinary(int num, int option){
	if (num < 1) {
		return;
	}
	int quotient = num / 2;
	int remainder = num % 2;
	convertToBinary(quotient,option);
	if (option == 1) {
		setPlainTextBits(remainder);
	}
	else {
		setKeyBits(remainder);
	}
	
}

void SDES::halfBits(string &bits, int option){
	int i = 0;

	if (option == 1) {
		/* Clear any values for R and L from previous round */
		if (getR().length() > 0) {
			getR().clear();
			getL().clear();
		}
	}
	else {
		/* Clear any values for R1 and R2 from previous round */
		if (getR1()->length() > 0) {
			getR1()->clear();
			getR2()->clear();
		}
	}

	while (bits[i] != '\0') {
		/* Option 1: Splits bit into R and L */
		if (option == 1) {
			if (i > 5) {
				setR(bits[i]);
			}
			else {
				setL(bits[i]);
			}
		}
		/* Option 2: Splits bit into R1 and R2 */
		else {
			if (i > 3) {
				setR2(bits[i]);
			}
			else {
				setR1(bits[i]);
			}
		}
		i++;
	}
}

void SDES::insertZeros(int num){
	int i = 0, count = 0, zerosToAdd;
	string modifyBits;

	/* If num is 1, modify plainTextBits
	   else modify key bits */
	if (num == 1) {
		modifyBits = getPlainTextBits();
	}
	else {
		modifyBits = getKeyBits();
	}

	// Find the length of the string of bits
	while(modifyBits[i] != '\0') {
		i++;
		count++;
	}

	/* Add zeros to the beginning of the stong of bits if the length < 12
	   for the plaintext bits and if length < 9 for the key bits*/
	if (num == 1) {
		zerosToAdd = 12 - count;
	}
	else {
		zerosToAdd = 9 - count;
	}
	count = 0;
	while(count < zerosToAdd) {
		modifyBits.insert(0, to_string(0));
		count++;
	}

	// Send bits back to the respectful string
	if (num == 1) {
		setPlainTextBits(modifyBits);
	}
	else {
		setKeyBits(modifyBits);
	}
}

void SDES::print(){
	printf("%s =  %d (%s); %s =  %d (%s)\n\n", "PlainText", binaryToDecimal(getPlainTextBits()), getPlainTextBits().c_str(),
			"key", binaryToDecimal(getKeyBits()), getKeyBits().c_str());
	string left = "L", right = "R";
	int counter = 0;
	auto it = getLRList().begin();
	for (it; it != getLRList().end(); ++it) {
		printf("%s%s =  %d (%s);  ", left.c_str(), to_string(counter).c_str(), binaryToDecimal(it->L), it->L.c_str());
		printf("%s%s =  %d (%s) \n", right.c_str(), to_string(counter).c_str(), binaryToDecimal(it->R), it->R.c_str());
		printf("--------------------------------------------- \n");
		counter++;
	}
	it = getLRList().begin();
	advance(it, 4);
	printf("%s =  %d (%s)\n\n", "Ciphertext", binaryToDecimal(it->cipherTextBits), it->cipherTextBits.c_str());
	printf("=============================================");
}

void SDES::generateK(string &keyBits){
	int round = 0;
	int decimalValueOfkBits = binaryToDecimal(keyBits);
	while (round < 4) {
		if (getIthKeyBits().length() > 0) {
			getIthKeyBits().clear();
		}

		/* Rotate bits by current round number */
		rotateBits(round);
		
		/* Only keep the first 8 bits after the shift */
		getIthKeyBits().erase(8);
		if (getKeyList().empty()) {
			getKeyList().push_front(getIthKeyBits());
		}
		else {
			getKeyList().push_back(getIthKeyBits());
		}
		round++;
	}
}

void SDES::rotateBits(int &shift){
	string originalKey = getKeyBits();
	string leadingBitsRemoved = "";
	int i = 0;
	/* First get the bits that will be shifted */
	for (i; i < shift; i++) {
		leadingBitsRemoved += originalKey[i];
	}
	/* Erase the bits from the original key that 
	   were included in the for loop */
	originalKey.erase(0,shift);

	if (getIthKeyBits().length() > 0) {
		getIthKeyBits().clear();
	}
	/* Make the ithKeyBits from the updated original key */
	getIthKeyBits().append(originalKey);

	/* Add the leadingBitsRemoved to the back of the ithKey string*/
	getIthKeyBits().append(leadingBitsRemoved);
}

void SDES::expandBits(string &R){
	int index = 2;

	/* Insert the 4th element from getR() into the 2nd index of R*/
	R.insert(index, getR(), 3, 1);

	/* Insert the updated 4th element from getR() into the 5th index of R*/
	index = 5;
	R.insert(index, getR(), 3, 1);
}

void SDES::xorStrings(string &str1, string &str2, int option){
	string xorStrings = "";
	string result = "";
	int i = str1.length() - 1;
	for (i; i > -1; i--) {
		if (result.length() > 0) {
			result.clear();
		}
		string ri(1, str1[i]);
		string ki(1, str2[i]);

		if ((str1[i] == '1' && str2[i] == '1') || (str1[i] == '0' && str2[i] == '0')) {
			result += "0";
		}
		else {
			result += "1";
		}
		
		/* Append to xorRK*/
		if (xorStrings.empty()) {
			xorStrings.append(result);
		}
		else {
			xorStrings.insert(0, result);
		}
	}
	/* Update R value */
	getR().clear();
	setR(xorStrings);

	if (option == 1) {
		/* Split R into R1 and R2 with
		   int 2 to activate 2nd option */
		halfBits(getR(), 2);
	}
}

void SDES::rkFunction(string *R1, string *R2, string S1[][8], string S2[][8]){
	int row, column, ptrIndex = 1, *ptrRow = &row, *ptrCol = &column;
	string col1 = "", col2 = "";

	if (getR().length() > 0) {
		getR().clear();
	}

	/* Get the row value for R1 */
	if (R1->at(0) == '0'){
		row = 0;
	}
	else {
		row = 1;
	}

	/* Populate col1 string*/
	while (ptrIndex < 4) {
		col1 += R1->at(ptrIndex);
		ptrIndex++;
	}

	/* Convert col1 from binary to decimal */
	column = binaryToDecimal(col1);

	/* Retrieve S_box value for R1 */
	string newR1 = getSboxValue(ptrRow, ptrCol, S1);
	setR(newR1);

	/* Get the row value for R2 */
	if (R2->at(0) == '0') {
		row = 0;
	}
	else {
		row = 1;
	}

	/* Populate col2 string*/
	ptrIndex = 1;
	while (ptrIndex < 4) {
		col2 += R2->at(ptrIndex);
		ptrIndex++;
	}

	/* Convert col2 from binary to decimal */
	column = binaryToDecimal(col2);

	/* Retrieve S_box value for R2 */
	string newR2 = getSboxValue(ptrRow, ptrCol, S2);
	setR(newR2);
}

void SDES::setL(char &bit) {
	int b = bit - 48;
	getL().append(to_string(b));
}

void SDES::setR(char &bit) {
	int b = bit - 48;
	getR().append(to_string(b));
}

void SDES::setR(string & updateRBits){
	getR().append(updateRBits);
}

void SDES::setR1(char &bit){
	int b = bit - 48;
	getR1()->append(to_string(b));
}

void SDES::setR2(char &bit){
	int b = bit - 48;
	getR2()->append(to_string(b));
}

void SDES::setList(string l, string r){
	LRPair pair;
	pair.L = getL();
	pair.R = getR();
	if (getLRList().empty()) {
		getLRList().push_front(pair);
	}
	else {
		getLRList().push_back(pair);
	}
}

void SDES::setCipherTextBits(string bits){
	getCipherTextBits().clear();
	getCipherTextBits().assign(bits);
}

void SDES::setCipherText(int bit){
	getCipherTextBits().append(to_string(bit));
}

void SDES::setPlainTextBits(int bit){
	getPlainTextBits().append(to_string(bit));
}

void SDES::setPlainTextBits(string modifiedBits){
	getPlainTextBits().clear();
	getPlainTextBits().assign(modifiedBits);
}

void SDES::setIthKeyBits(int bit){
	getIthKeyBits().append(to_string(bit));
}

void SDES::setKeyBits(int bit){
	getKeyBits().append(to_string(bit));
}

void SDES::setKeyBits(string modifiedBits){
	getKeyBits().clear();
	getKeyBits().assign(modifiedBits);
}


/*********************************
 *	Functions with return values *
 *********************************/

int SDES::binaryToDecimal(string &binary){
	string num = binary;
	int decimal = 0;

	// Initializing base value to 1, i.e 2^0 
	int base = 1;

	int len = num.length();
	for (int i = len - 1; i >= 0; i--){
		if (num[i] == '1')
			decimal += base;
		base = base * 2;
	}
	return decimal;
}

int SDES::getPlainText() {
	return plainText;
}

int SDES::getCipherText(){
	return ciphertext;
}

int SDES::getKey() {
	return key;
}

list<LRPair> & SDES::getLRList(){
	return LR;
}

list<string> & SDES::getKeyList(){
	return k;
}

string & SDES::getL(){
	return L;
}

string & SDES::getR(){
	return R;
}

string* SDES::getR1(){
	return &R1;
}

string* SDES::getR2(){
	return &R2;
}

string & SDES::getPlainTextBits(){
	return plainTextBits;
}

string & SDES::getKeyBits(){
	return keyBits;
}

string & SDES::getIthKeyBits(){
	return ithKey;
}

string & SDES::getConcatedBits(){
	return concatedBits;
}

string & SDES::getCipherTextBits(){
	return cipherTextBits;
}

string SDES::getSboxValue(int *row, int *col, string S_box[][8]) {
	/* return value at dereference location*/
	return S_box[*row][*col];
}
	


