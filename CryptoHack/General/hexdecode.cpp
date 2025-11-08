#include <bits/stdc++.h>
#include <cryptopp/hex.h> 
#include <cryptopp/filters.h>

using namespace CryptoPP; 
using namespace std;

int main(){
    string encoded = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"; 
    string decoded; 
    StringSource ss(encoded, true, new HexDecoder(
        new StringSink(decoded)
    )
);
    cout << decoded; 
    return 0; 
}
