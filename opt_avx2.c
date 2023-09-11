#include <stdio.h> 
#include <string.h> 
#include <stdint.h> 
#include <xmmintrin.h> 
#include <emmintrin.h> 
#include <immintrin.h> 
#include <x86intrin.h>

#include <stdlib.h> 
#include <time.h>

// round of block cipher 
#define NUM_ROUND 80

// size of plaintext and key size
#define BLOCK_SIZE 512
#define P_K_SIZE 2
#define SESSION_KEY_SIZE NUM_ROUND

// basic operation
#define ROR(x,r) ((x>>r) | (x<<(32-r))) 
#define ROL(x,r) ((x<<r) | (x>>(32-r)))

// example: AVX2 functions; freely remove this code and write what you want in here! 
#define INLINE inline __attribute__((always_inline))

// #define LOAD(x) _mm256_loadu_si256((__m256i*)x) 
#define LOAD(x) _mm256_setr_epi32(x[0], x[2], x[4], x[6], x[8], x[10], x[12], x[14]) // 변경 : LOAD를 uin32_t 자료형에서 건너뛰면서 받아옴
// #define STORE(x,y) _mm256_storeu_si256((__m256i*)x, y) 
#define STORE(x, y) (x[0]=y[0]; x[2]=y[1]; x[4]=y[2]; x[6]=y[3]; x[8]=y[4]; x[10]=y[5]; x[12]=y[6]; x[14]=y[7];)
#define XOR(x,y) _mm256_xor_si256(x,y)
#define OR(x,y) _mm256_or_si256(x,y)
#define AND(x,y) _mm256_and_si256(x,y)
#define SHUFFLE8(x,y) _mm256_shuffle_epi8(x,y)
#define ADD(x,y) _mm256_add_epi32(x,y)
#define SHIFT_L(x,r) _mm256_slli_epi32(x,r)
#define SHIFT_R(x,r) _mm256_srli_epi32(x,r)
#define ROR_AVX2(x, r) (SHIFT_R(x,r) | SHIFT_L(x, 32-r)) // 추가 : right rotation
#define ROL_AVX2(x, r) (SHIFT_L(x,r) | SHIFT_R(x, 32-r)) // 추가 : left rotation

int64_t cpucycles(void)
{
    unsigned int hi, lo;
    __asm__ __volatile__ ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32); 
}

// 64-bit data
// 64-bit key
// 32-bit x 22 rounds session key
void new_key_gen(uint32_t* master_key, uint32_t* session_key){
    uint32_t i=0;
    uint32_t k1, k2, tmp; 
    k1 = master_key [0]; 
    k2 = master_key [1];

    for (i=0;i<NUM_ROUND;i++){ 
        k1 = ROR(k1, 8);
        k1 = k1 + k2;
        k1 = k1 ^ i;
        k2 = ROL(k2, 3);
        k2 = k1 ^ k2; 
        session_key[i] = k2;
    } 
}

void new_block_cipher(uint32_t* input, uint32_t* session_key, uint32_t* output){
    uint32_t i=0;
    uint32_t pt1, pt2, tmp1, tmp2;
    pt1 = input[0]; 
    pt2 = input[1];
    for (i=0;i<NUM_ROUND;i++){ 
        tmp1 = ROL(pt1,1); 
        tmp2 = ROL(pt1,8);
        tmp2 = tmp1 & tmp2;
        tmp1 = ROL(pt1,2);
        tmp2 = tmp1 ^ tmp2;
        pt2 = pt2 ^ tmp2;
        pt2 = pt2 ^ session_key[i];

        tmp1 = pt1; 
        pt1 = pt2;
        pt2 = tmp1;
    }
    output[0] = pt1;
    output[1] = pt2;
}

// key gen, block cipher을 합친 함수
// 8*64-bit key
// 8*64-bit input data
// 8*64-bit output data
void new_keygen_blockcipherAVX2(uint32_t *master_key, uint32_t* input, uint32_t* output) {
    
    // rounds
    int r;

    // keygen params
    __m256i k8_1, k8_2, i, one_vector; // 8블록의 k1부분, 8블록의 k2부분, 
    i = _mm256_setr_epi32(0,0,0,0,0,0,0,0); // zero vector
    one_vector = _mm256_setr_epi32(1,1,1,1,1,1,1,1); // one vector

    // k8_1, k8_2 로드
    k8_1 = LOAD(master_key); // _mm256_setr_epi32(master_key[0], master_key[2], master_key[4], master_key[6], master_key[8], master_key[10], master_key[12], master_key[14]);
    k8_2 = LOAD((master_key+1)); // _mm256_setr_epi32(master_key[1], master_key[3], master_key[5], master_key[7], master_key[9], master_key[11], master_key[13], master_key[15]);

    // cipher params
    __m256i tmp, p8_1, p8_2; // 8블록의 p1, 8블록의 p2, 8블록의 p1을 임시저장할 tmp 변수
    uint32_t *output8; // output을 옮기기 위함
    // pt 로드
    p8_1 = LOAD(input); // _mm256_setr_epi32(input[0], input[2], input[4], input[6], input[8], input[10], input[12], input[14]);
    p8_2 = LOAD((input+1)); // _mm256_setr_epi32(input[1], input[3], input[5], input[7], input[9], input[11], input[13], input[15]);

    for (r=0; r<NUM_ROUND; r++) {

        // keygen
        k8_1 = ROR_AVX2(k8_1, 8);
        k8_1 = ADD(k8_1, k8_2);
        k8_1 = XOR(k8_1, i);
        k8_2 = ROL_AVX2(k8_2, 3);
        k8_2 = XOR(k8_1, k8_2); // k8_2가 8블록 세션 키로 작용함
        i = ADD(i,one_vector);

        // cipher 
        tmp = p8_1;
        p8_1 = XOR( XOR( XOR( AND( ROL_AVX2(p8_1, 1), ROL_AVX2(p8_1, 8)), ROL_AVX2(p8_1, 2)), p8_2), k8_2);
        p8_2 = tmp;

    }

    output8 = (uint32_t *)&p8_1;
    // STORE(output, output8);
    output[0]=output8[0];
    output[2]=output8[1];
    output[4]=output8[2];
    output[6]=output8[3];
    output[8]=output8[4];
    output[10]=output8[5];
    output[12]=output8[6];
    output[14]=output8[7];

    output8 = (uint32_t *)&p8_2;
    // STORE((output+1), output8);
    output[1]=output8[0];
    output[3]=output8[1];
    output[5]=output8[2];
    output[7]=output8[3];
    output[9]=output8[4];
    output[11]=output8[5];
    output[13]=output8[6];
    output[15]=output8[7];

    // 23.7.28 03:00 // __mm256_setr_epi32 의 역함수, 즉 256bit -> 32bit array로 store할 수 있는 방법 알아보기.
}

int main(){
    long long int kcycles, ecycles, dcycles; 
    long long int cycles1, cycles2;
    int32_t i, j;

    // C implementation
    uint32_t input_C[BLOCK_SIZE][P_K_SIZE]={0,};
    uint32_t key_C[BLOCK_SIZE][P_K_SIZE]={0,};
    uint32_t session_key_C[BLOCK_SIZE][SESSION_KEY_SIZE]={0,}; 
    uint32_t output_C[BLOCK_SIZE][P_K_SIZE]={0,};
    
    // AVX implementation
    uint32_t input_AVX[BLOCK_SIZE][P_K_SIZE]={0,};
    uint32_t key_AVX[BLOCK_SIZE][P_K_SIZE]={0,};
    uint32_t session_key_AVX[BLOCK_SIZE][SESSION_KEY_SIZE]={0,}; 
    uint32_t output_AVX[BLOCK_SIZE][P_K_SIZE]={0,};

    // random generation for plaintext and key. 
    srand ( 0 );
    for(i=0;i<BLOCK_SIZE;i++){ 
        for(j=0;j<P_K_SIZE;j++){
            input_AVX[i][j] = input_C[i][j] = rand();
            key_AVX[i][j] = key_C[i][j] = rand(); 
        }
    }

    // execution of C implementation kcycles=0;
    cycles1 = cpucycles(); 
    for(i=0;i<BLOCK_SIZE;i++){
        new_key_gen(key_C[i], session_key_C[i]);
        new_block_cipher(input_C[i], session_key_C[i], output_C[i]); 
    }
    cycles2 = cpucycles();
    kcycles = cycles2-cycles1;
    printf("C    implementation runs in ................. %8lld cycles", kcycles/BLOCK_SIZE);
    printf("\n");

    // KAT and Benchmark test of AVX implementation 
    kcycles=0;
    cycles1 = cpucycles();

    ///////////////////////////////////////////////////////////////////////////////////////////
    //These functions (new_key_gen, new_block_cipher) should "new_key_gen_AVX2" and "new_block_cipher_AVX2".

    for(i=0;i<BLOCK_SIZE/8;i++){
        new_keygen_blockcipherAVX2(key_AVX[8*i], input_AVX[8*i], output_AVX[8*i]);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    for(i=0;i<BLOCK_SIZE;i++){ 
        for(j=0;j<P_K_SIZE;j++){
            if(output_C[i][j] != output_AVX[i][j]){ 
                printf("Test failed!!!\n");
                return 0; 
            }
        }
    }
    
    cycles2 = cpucycles();
    kcycles = cycles2-cycles1;
    printf("AVX implementation runs in ................. %8lld cycles", kcycles/BLOCK_SIZE); printf("\n");
    printf("\n");
}