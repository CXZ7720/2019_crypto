/*
 * @file    rsa.c
 * @author  김영균 / 2015038140
 * @date    11/10
 * @brief   mini RSA implementation code
 * @details 세부 설명
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rsa.h"

llint p, q, e, d, n;

/*
 * @brief     모듈러 덧셈 연산을 하는 함수.
 * @param     llint a     : 피연산자1.
 * @param     llint b     : 피연산자2.
 * @param     byte op    : +, - 연산자.
 * @param     llint n      : 모듈러 값.
 * @return    llint result : 피연산자의 덧셈에 대한 모듈러 연산 값. (a op b) mod n
 * @todo      모듈러 값과 오버플로우 상황을 고려하여 작성한다.
 */
llint ModAdd(llint a, llint b, byte op, llint n) {
    llint result = 0;

    if(b == 0){
        result = a;
    }
    b = n - b;
    if(a >= b){
        result =  a - b;
    } else {
        result =  n - b + a;
    }

    return result;
}

/*
 * @brief      모듈러 곱셈 연산을 하는 함수.
 * @param      llint x       : 피연산자1.
 * @param      llint y       : 피연산자2.
 * @param      llint n       : 모듈러 값.
 * @return     llint result  : 피연산자의 곱셈에 대한 모듈러 연산 값. (a x b) mod n
 * @todo       모듈러 값과 오버플로우 상황을 고려하여 작성한다.
 */
llint modMul(llint x, llint y, llint n) {
    llint result = 0;
    llint t1 = x;
    if(x == 0 || y == 0){
        result = 0;
    }
    if(x == 1){
        result = y;
    }
    if(y == 1){
        result = x;
    }
    while(y > 0){
        if((y & 0x01) == 0x01){
            result = ModAdd(result, t1, '+',n);
        }
        t1 = ModAdd(t1, t1, '+', n);
        y = y >> 1;
        //>> 연산 == 2로 나누기
        // <<연산 == 2로 거듭제곱.
    }


    return result;
}

/*
 * @brief      모듈러 거듭제곱 연산을 하는 함수.
 * @param      llint base   : 피연산자1.
 * @param      llint exp    : 피연산자2.
 * @param      llint n      : 모듈러 값.
 * @return     llint result : 피연산자의 연산에 대한 모듈러 연산 값. (base ^ exp) mod n
 * @todo       모듈러 값과 오버플로우 상황을 고려하여 작성한다.
               'square and multiply' 알고리즘을 사용하여 작성한다.
 */
llint modPow(llint base, llint exp, llint mod){

    llint result = 1;
    if(base == 1){
        return 0;
    }
    while (exp > 0){
        result = modMul(result, base, mod);
        base = modMul(base, base, mod);
        exp = exp >> 1; // 2로 나누기
    }


    return result;
}

/*
 * @brief      입력된 수가 소수인지 입력된 횟수만큼 반복하여 검증하는 함수.
 * @param      llint testNum   : 임의 생성된 홀수.
 * @param      llint repeat    : 판단함수의 반복횟수.
 * @return     llint result    : 판단 결과에 따른 TRUE, FALSE 값.
 * @todo       Miller-Rabin 소수 판별법과 같은 확률적인 방법을 사용하여,
               이론적으로 4N(99.99%) 이상 되는 값을 선택하도록 한다. 
 */
bool isPrime(llint testNum, llint repeat) {
    llint result = FALSE;
    llint a, b;
    int k = 0;
    llint m = testNum - 1;
    while ((m & 1) == 0) {//2로 나눈 나머지(비트연산자 AND 를 이용  == 0
        m = m >> 1;
        k++;
    }
    for (int i = 0; i < 100; i++) {
        int rnd = WELLRNG512a() * 1000000;
        a = rnd * (testNum -2);
        if (a < 2)
        {
            a = 2;
        }
        if(GCD(a,n) != 1)
        {
            return FALSE;
        }
        b = modPow(a,m,n);
        if(b == 1 || b == (n-1)){
            continue;
        } else {
            for (int j = 0; j < k-1; j++) {
                b = (b * b) & (n -1); //비트연산자를 이용해서 n 으로 나눈 나머지를 구함.
                if(b == (n-1)){
                    break;
                }
            }
            if(b != (n-1)){
                return FALSE;
            }
        }

    }
    result = TRUE;
    return result;
}

//몫 구하는 함수
llint quot(llint a, llint b){
    llint  count = 1; //몫
    while(a > b){
        a -= b;
        count ++;
    }
    return count;
}

//나머지 함수
llint extra(llint a, llint b){
    while(a >= b){
        a -= b;
    }
    llint extra = a;
    return extra;
}



/*
 * @brief       모듈러 역 값을 계산하는 함수.
 * @param       llint a      : 피연산자1.
 * @param       llint m      : 모듈러 값.
 * @return      llint result : 피연산자의 모듈러 역수 값.
 * @todo        확장 유클리드 알고리즘을 사용하여 작성하도록 한다.
 */
llint modInv(llint a, llint m) {
    llint result = 0;
    llint qt, rm;

    /*gcd(a,b) = ax+by*/
    llint s0 = 0, t0 = 0, x0 = 1, x1 = 0, y0 = 0, y1 = 1;

    while(m > 0){
        qt = quot(a,m);
        rm = extra(a,m);
//        printf("a : %u\n", a);
//        printf("m : %u\n", m);
//
//
//        printf("qt : %u\n", qt);
//        printf("rm : %u\n", rm);

        s0 = x0 - qt * x1;
        t0 = y0 - qt * y1;

        x0 = x1, x1 = s0;
        y0 = y1, y1 = t0;

        a = m;
        m = rm;
    }

    if (a == 1){
        result = rm;
    }

    return result;
}

/*
 * @brief     RSA 키를 생성하는 함수.
 * @param     llint *p   : 소수 p.
 * @param     llint *q   : 소수 q.
 * @param     llint *e   : 공개키 값.
 * @param     llint *d   : 개인키 값.
 * @param     llint *n   : 모듈러 n 값.
 * @return    void
 * @todo      과제 안내 문서의 제한사항을 참고하여 작성한다.
 */
void miniRSAKeygen(llint *p, llint *q, llint *e, llint *d, llint *n) {
    *p = 3;
    *q = 7;
    *e = 5;
    llint pie_n;
//    printf("pie_n : %u\n",pie_n);
    *n = *p * *q;
//    printf("%d\n", *n);
    pie_n = (*p -1) * (*q -1);
//    printf("updated_pie_n : %u",pie_n);

    *d = modInv(pie_n, *e);
//    printf("d: %d\n", *d);

    while(e < pie_n){
        if(GCD(e, pie_n) == 1){
            break;
        } else{
          e++;
        }
    }

}

/*
 * @brief     RSA 암복호화를 진행하는 함수.
 * @param     llint data   : 키 값.
 * @param     llint key    : 키 값.
 * @param     llint n      : 모듈러 n 값.
 * @return    llint result : 암복호화에 결과값
 * @todo      과제 안내 문서의 제한사항을 참고하여 작성한다.
 */
llint miniRSA(llint data, llint key, llint n) {
    llint result;
//    printf("입력값 : %u\n", data);
    result = modPow(data, key, n);
//    printf("출력값 : %u\n", result);
    return result;
}

llint GCD(llint a, llint b) {
    llint prev_a;

    while(b != 0) {
//        printf("GCD(%lld, %lld)\n", a, b);
        prev_a = a;
        a = b;
        while(prev_a >= b) prev_a -= b;
        b = prev_a;
    }
//    printf("GCD(%lld, %lld)\n\n", a, b);
    return a;
}

int main(int argc, char* argv[]) {
//    printf("Starting Program!\n");
    byte plain_text[4] = {0x12, 0x34, 0x56, 0x78};
    llint plain_data, encrpyted_data, decrpyted_data;
    uint seed = time(NULL);
    memcpy(&plain_data, plain_text, 4);

    // 난수 생성기 시드값 설정
    seed = time(NULL);
    InitWELLRNG512a(&seed);

    // RSA 키 생성
    printf("keygen start\n");
    miniRSAKeygen(&p, &q, &e, &d, &n);
    printf("0. Key generation is Success!\n ");
    printf("p : %lld\n q : %lld\n e : %lld\n d : %lld\n N : %lld\n\n", p, q, e, d, n);

    // RSA 암호화 테스트
    encrpyted_data = miniRSA(plain_data, e, n);
    printf("1. plain text : %lld\n", plain_data);    
    printf("2. encrypted plain text : %lld\n\n", encrpyted_data);

    // RSA 복호화 테스트
    decrpyted_data = miniRSA(encrpyted_data, d, n);
    printf("3. cipher text : %lld\n", encrpyted_data);
    printf("4. Decrypted plain text : %lld\n\n", decrpyted_data);

    // 결과 출력
    printf("RSA Decryption: %s\n", (decrpyted_data == plain_data) ? "SUCCESS!" : "FAILURE!");

    return 0;
}