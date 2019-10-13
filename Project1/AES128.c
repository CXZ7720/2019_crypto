/*  ======================================================================== *

                                    주 의 사 항


    1. 구현은 다양한 방식으로 이뤄질 수 있음
    2. AES128(...) 함수의 호출과 리턴이 여러번 반복되더라도 메모리 누수가 생기지 않게 함
    3. AddRoundKey 함수를 구현할 때에도 파라미터 rKey는 사전에 선언된 지역 배열을 가리키도록 해야 함
       (정확한 구현을 위해서는 포인터 개념의 이해가 필요함)
    4. 배열의 인덱스 계산시 아래에 정의된 KEY_SIZE, ROUNDKEY_SIZE, BLOCK_SIZE를 이용해야 함
       (상수 그대로 사용하면 안됨. 예로, 4, 16는 안되고 KEY_SIZE/4, BLOCK_SIZE로 사용해야 함)

 *  ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AES128.h"

#define KEY_SIZE 16
#define ROUNDKEY_SIZE 176
#define BLOCK_SIZE 16

/* 기타 필요한 전역 변수 추가 선언 */
BYTE S_BOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

BYTE insBox[256];

BYTE  Rcon[10][4] = {
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {0x80, 0x00, 0x00, 0x00},
        {0x1b, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00},
};


/* 기타 필요한 함수 추가 선언 및 정의 */
BYTE findSboxVal(int num, int mode){
    for (int i = 0; i < 256; i++) {
        insBox[S_BOX[i]] = i;
    }
    if (mode == 0){
        //ENC 모드
        return S_BOX[num];
    } else {
        //DEC 모드
        return insBox[num];
    }
}

BYTE shiftMatrix(BYTE * mat, int from){
    //매트릭스 이동함수
    //0행 이동X
    //1행 좌측 1칸
    //2행 좌측 2칸
    //3행 좌측 3칸

    BYTE temp_mat[4];

    int move;
    move = from * 4 + from;

    for (int i = 0; i < BLOCK_SIZE/4; i++) {
        temp_mat[i] = *(mat + move);
        move += 4;
        if(move >= BLOCK_SIZE){
            move = from;
        }
    }
    move = from;
    for (int j = 0; j < BLOCK_SIZE/4; j++) {
        *(mat + move) = temp_mat[j];
        move += 4;
    }

}
BYTE baseMat[4][4] = {
        {2,3,1,1,},
        {1,2,3,1},
        {1,1,2,3},
        {3,1,1,2}
};

BYTE inversebaseMat[4][4] = {
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d},
    {0x0d, 0x09, 0x0e, 0x0b},
    {0x0b, 0x0d, 0x09, 0x0e}
};

BYTE xtime(BYTE x){
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}
#define GF8(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ \
((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ \
((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))
//GF(2^8) = x^8 + x^4 + x^3 + x + 1 연산을 수행.


BYTE unitMult(BYTE a, BYTE b){
    switch(a){
        case 2:
            b = xtime(b);
        case 3:
            b = b ^ xtime(b);
        case 4:
            b = GF8(a,b);
    }
    return b;
}

BYTE matrixMult(BYTE * matrix, BYTE targetMatrix[4][4]){
    BYTE result[16];
    BYTE calc[4][4];
    int idx;
    int i, j;

    memset(result, 0, sizeof(BYTE)*BLOCK_SIZE); //리턴배열 초기화
    memcpy(calc, targetMatrix, sizeof(BYTE)*BLOCK_SIZE);//파라미터로 가져온 배열 준비

    for (i = 0; i < BLOCK_SIZE/4; i++) {
        for (j = 0; j < BLOCK_SIZE/4; j++) {
            result[i+j*(BLOCK_SIZE/4)] =\
            unitMult(calc[j][0], *(matrix + i * (BLOCK_SIZE/4) + 0)) ^ \
            unitMult(calc[j][1], *(matrix + i * (BLOCK_SIZE/4) + 1)) ^ \
            unitMult(calc[j][2], *(matrix + i * (BLOCK_SIZE/4) + 2)) ^ \
            unitMult(calc[j][3], *(matrix + i * (BLOCK_SIZE/4) + 3));
        }
        
    }

    for (idx = 0;  idx< BLOCK_SIZE; idx++) {
        *(matrix + idx) = result[idx];
    }

}

BYTE * rotationWord(BYTE *word){
    BYTE temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;

    return word;
}

void subByte(BYTE * word){
    for (int i = 0; i < BLOCK_SIZE/4; i++) {
        *(word + i) = S_BOX[word[i]];
    }
}

void xorword(BYTE * word, BYTE * rword, BYTE * temp){
    for (int i = 0; i < BLOCK_SIZE/4; i++) {
        *(word+i) = *(rword+i) ^ *(temp+i);
    }
}


/*  <키스케줄링 함수>
 *   
 *  key         키스케줄링을 수행할 16바이트 키
 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
 */
void expandKey(BYTE *key, BYTE *roundKey){

    /* 추가 구현 */
    BYTE temp[4];

    for (int i = 0; i < BLOCK_SIZE/4 ; ++i) {
        roundKey[(i * 4) + 0] = key[(i * 4) + 0];
        roundKey[(i * 4) + 1] = key[(i * 4) + 1];
        roundKey[(i * 4) + 2] = key[(i * 4) + 2];
        roundKey[(i * 4) + 3] = key[(i * 4) + 3];
    }

    for (int i = BLOCK_SIZE / 4; i < (BLOCK_SIZE/4)*(sizeof(Rcon)/ sizeof(BYTE) + 1); i++){
        int k = (i - 1) * 4;

        temp[0] = roundKey[k + 0];
        temp[1] = roundKey[k + 1];
        temp[2] = roundKey[k + 2];
        temp[3] = roundKey[k + 3];

        subByte(rotationWord(temp));

        int j = i * 4;
        int t = (i - BLOCK_SIZE/4)*4;
        roundKey[j + 0] = roundKey[k + 0] ^ temp[0];
        roundKey[j + 1] = roundKey[k + 1] ^ temp[1];
        roundKey[j + 2] = roundKey[k + 2] ^ temp[2];
        roundKey[j + 3] = roundKey[k + 3] ^ temp[3];

    }


//    memcpy(roundKey,key, sizeof(BYTE)*BLOCK_SIZE);
//    for (int i = BLOCK_SIZE; i < ROUNDKEY_SIZE; i+=(BLOCK_SIZE/4)) {
//        memcpy(temp,roundKey + i - (BLOCK_SIZE/4), BLOCK_SIZE/4);
//        if(i % BLOCK_SIZE == 0){ //1블록단위일 때 마다
//            subByte(rotationWord(temp)); //1칸씩 밀어내기
//            temp[0] = temp[0] ^ Rcon[i/BLOCK_SIZE]; //XOR 연산
//        }
//        xorword(roundKey + i, roundKey + i - BLOCK_SIZE, temp); //XOR 연산
//    }


}


/*  <SubBytes 함수>
 *   
 *  block   SubBytes 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    SubBytes 수행 모드
 */
 BYTE* subBytes(BYTE *block, int mode){

    /* 필요하다 생각하면 추가 선언 */

    switch(mode){

        case ENC:
            
            /* 추가 구현 */
            for (int i = 0; i < BLOCK_SIZE; i++) {
                *(block + i) = findSboxVal(*(block + i), 0); //S박스에서 인덱스에 해당하는 키를 찾아옴.
            }
            
            break;

        case DEC:

            /* 추가 구현 */
            for (int i = 0; i < BLOCK_SIZE; i++) {
                *(block + i) = findSboxVal(*(block + i), 1); //S박스에서 인덱스에 해당하는 키를 찾아옴.
            }
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}


/*  <ShiftRows 함수>
 *   
 *  block   ShiftRows 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    ShiftRows 수행 모드
 */
BYTE* shiftRows(BYTE *block, int mode){ 

    /* 필요하다 생각하면 추가 선언 */   

    switch(mode){

        case ENC:
            /* 추가 구현 */
            for (int i = 0; i < BLOCK_SIZE/4; i++) {
                shiftMatrix(block, i);
            }

            break;
        case DEC:
            /* 추가 구현 */
            for (int j = 0; j < BLOCK_SIZE/4; j++) {
                shiftMatrix(block,j);
                if( j == 1 || j == 3){
                    //총 3번 matrix shift를 하게 되면 right로 1번 shift 한 것과 같은 효과.
                    //0번째는 이동안함, 2번째는 이동결과 좌우같음.
                    shiftMatrix(block, j);
                    shiftMatrix(block, j);
                }
            }
            break;
        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}


/*  <MixColumns 함수>
 *   
 *  block   MixColumns을 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
 *  mode    MixColumns의 수행 모드
 */
BYTE* mixColumns(BYTE *block, int mode){    
    /* 필요하다 생각하면 추가 선언 */   

    switch(mode){

        case ENC:
            
            /* 추가 구현 */
            matrixMult(block, baseMat);
            
            break;

        case DEC:

            /* 추가 구현 */
            matrixMult(block, inversebaseMat);
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return block;
}

/*  <AddRoundKey 함수>
 *   
 *  block   AddRoundKey를 수행할 16바이트 블록. 수행 결과는 해당 배열에 반영
 *  rKey    AddRoundKey를 수행할 16바이트 라운드키
 */
BYTE* addRoundKey(BYTE *block, BYTE *rKey){
    /* 추가 구현 */

    for (int i = 0; i < BLOCK_SIZE; i++) {
        *(block + i) = *(block + i) ^ *(rKey + i);
    }
    return block;
}

/*  <128비트 AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  input   평문 바이트 배열
 *  result  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 *
 *  [DEC 모드]
 *  input   암호문 바이트 배열
 *  result  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 */
 
void AES128(BYTE *input, BYTE *result, BYTE *key, int mode){
    BYTE roundKey[ROUNDKEY_SIZE];
    expandKey(key, roundKey);

    if(mode == ENC){

        /* 추가 작업이 필요하다 생각하면 추가 구현 */
        addRoundKey(input, roundKey);
        for (int i = 1; i <= 9; i++) {//9라운드까지
            subBytes(input, mode);
            shiftRows(input, mode);
            mixColumns(input, mode);
            addRoundKey(input, roundKey + BLOCK_SIZE * 10);
        }
        subBytes(input, mode);
        shiftRows(input, mode);
        addRoundKey(input, roundKey);


    }else if(mode == DEC){

        /* 추가 작업이 필요하다 생각하면 추가 구현 */
        addRoundKey(input, roundKey);
        for(int i = 1; i <= 9; i++){
            subBytes(input, mode);
            shiftRows(input, mode);
            mixColumns(input, mode);
            mixColumns(roundKey + ((sizeof(Rcon)/sizeof(BYTE) - i) * BLOCK_SIZE), mode);
            addRoundKey(input, roundKey + (((sizeof(Rcon)/sizeof(BYTE) - i) * BLOCK_SIZE)));
        }
        subBytes(input, mode);
        shiftRows(input, mode);
        addRoundKey(input, roundKey);

    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}
