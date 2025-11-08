#include <bits/stdc++.h>
#include <iostream>
using namespace std;

int main(){
    ios_base::sync_with_stdio(false);

    vector<int> a = {99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125};
    string flag = ""; 
    for (size_t i = 0 ; i < a.size();i++){
        flag += char(a[i]); 
    }
    cout << flag << endl;
    return 0;
}
