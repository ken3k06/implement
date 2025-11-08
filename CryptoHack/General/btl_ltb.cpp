#include <bits/stdc++.h>
#include <cryptopp/integer.h>

using namespace std;
using namespace CryptoPP; 

Integer bytes_to_long(const vector<CryptoPP::byte> &bytes){
    return Integer(bytes.data(),bytes.size()); 
}

vector<CryptoPP::byte> long_to_bytes(const Integer &n){
    size_t len = n.MinEncodedSize(); 
    vector<CryptoPP::byte> v(len); 
    n.Encode((CryptoPP::byte*)&v[0], v.size(), Integer::UNSIGNED); 
    return v;
}

int main() {
    Integer n("11515195063862318899931685488813747395775516287289682636499965282714637259206269");
    vector <CryptoPP::byte> V = long_to_bytes(n); 
    for (auto c: V){
        cout << c; 
    }
    
    return 0;
}
