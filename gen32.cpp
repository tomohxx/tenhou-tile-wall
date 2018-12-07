#include <stdio.h>
#include <utility>
#define BUFFERSIZE BUFSIZ
#include <b64/decode.h>
#include <openssl/sha.h>
#include "mt19937ar.h"
#define MTRAND_N 624
#define DWORD unsigned long//4バイト, 32ビット
#define BYTE unsigned char//1バイト, 8ビット

//mjlogに記されている<SHUFFLE seed="mt19937ar-sha512-n288-base64,~> 3328文字
//http://tenhou.net/0/?log=2014021221gm-00a9-0000-23324af3 (牌山生成検証コード(完成))
//char MTseed_b64[] = "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";
//http://tenhou.net/0/?log=2016022509gm-0009-0000-b327da61 (牌山生成方法の検証用データ)
//char MTseed_b64[] = "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";
//http://tenhou.net/0/?log=2017020100gm-00e1-0000-17d39cdb (2017/02/01 | 00:00 | 14 | 四鳳東喰赤一)
char MTseed_b64[] = "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";

const char *haiDisp[34] = {
    "<1m>", "<2m>", "<3m>", "<4m>", "<5m>", "<6m>", "<7m>", "<8m>", "<9m>",
    "<1p>", "<2p>", "<3p>", "<4p>", "<5p>", "<6p>", "<7p>", "<8p>", "<9p>",
    "<1s>", "<2s>", "<3s>", "<4s>", "<5s>", "<6s>", "<7s>", "<8s>", "<9s>",
    "<東>", "<南>", "<西>", "<北>", "<白>", "<發>", "<中>"
};

void convertEndian(DWORD* input)
{
    *input = (((*input)&0x00FF00FF)<<8)|(((*input)&0xFF00FF00)>>8);
    *input = (((*input)&0x0000FFFF)<<16)|(((*input)&0xFFFF0000)>>16);
}
 
int main()
{
    unsigned char MTseed[MTRAND_N*4+1];// 4992+1(終了コード追加用の+1)
    base64::decoder D;// base64デコーダ

    //base64デコード
    D.decode(MTseed_b64, sizeof(MTseed_b64)/sizeof(*MTseed_b64), (char*)MTseed);
  
    //MTseedをDWORD[]に変換
    DWORD RTseed[MTRAND_N];// ルートMTのシード
    
    //代入
    for(int i=0; i<MTRAND_N; i++){
        RTseed[i] = (MTseed[4*i]<<24)|(MTseed[4*i+1]<<16)|(MTseed[4*i+2]<<8)|MTseed[4*i+3];
    }

    //RTseedのエンディアン変換
    for(std::size_t i=0; i<sizeof(RTseed)/sizeof(*RTseed); ++i){
        convertEndian(&RTseed[i]);
    }
    
    //ルートMTを初期化
    init_by_array(RTseed, sizeof(RTseed)/sizeof(*RTseed));
 
    for(int nGame=0; nGame<10; ++nGame){
        //ローカルMTの乱数生成+SHA512
        DWORD rnd[SHA512_DIGEST_LENGTH/sizeof(DWORD)*9];// 135+2以上を確保
        DWORD src[sizeof(rnd)/sizeof(*rnd)*2];// 1024bit単位で512bitへhash

        //ローカルMTで乱数生成
        for(std::size_t i=0; i<sizeof(src)/sizeof(*src); ++i){
            src[i] = genrand_int32();
        }

        //ハッシュ計算
        for (std::size_t i=0; i<sizeof(rnd)/SHA512_DIGEST_LENGTH/*=9 */; ++i){
            SHA512_CTX ctx;
            SHA512_Init(&ctx);
            SHA512_Update(&ctx, (BYTE*)src+i*SHA512_DIGEST_LENGTH*2, SHA512_DIGEST_LENGTH*2); // in=1024bit
            SHA512_Final ((BYTE*)rnd+i*SHA512_DIGEST_LENGTH, &ctx); // out=512bit
        }
 
        //牌山シャッフル
        BYTE yama[136];

        for(int i=0; i<136; ++i){
            yama[i] = i;
        }

        for(int i=0; i<136-1; ++i){
            std::swap(yama[i], yama[i+(rnd[i]%(136-i))]);// 1/2^32以下の誤差は許容
        }
 
        //牌山表示
        printf("--------Game %d--------\r\n", nGame);
        printf("yama =\r\n");
        for (int i=0; i<136; ++i){
            printf("%s", haiDisp[yama[i]/4]);
            //printf("<%d>", yama[i]);
            if ((i+1)%17 == 0) printf("\r\n");
            if (i == 83) printf("  ");//配牌終了地点にスペースを挟む
        }
        printf("\r\n");
 
        //サイコロ表示
        int dice0 = rnd[135]%6;
        int dice1 = rnd[136]%6;
        printf("dice0 = %d, dice1 = %d\r\n\r\n\r\n", dice0+1, dice1+1);
        // rnd[137]～rnd[143]は未使用
    }

    return 0;
}