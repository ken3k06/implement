#include <bits/stdc++.h>
#include <cryptopp/hex.h> 
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

using namespace CryptoPP; 
using namespace std;

int main(){
    string encoded = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"; 
    string decoded; 
    string output; 
    StringSource ss(encoded, true, new HexDecoder(
        new StringSink(decoded)
    )
);
    StringSource(decoded, true,
    new Base64Encoder(new StringSink(output), 
false));
    cout << output << endl;
    
    return 0; 
}
