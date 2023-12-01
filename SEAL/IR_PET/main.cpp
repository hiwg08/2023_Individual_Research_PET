#include <bits/stdc++.h>
#include "seal/seal.h"
#include <opencv2/highgui.hpp>
#include <filesystem>

#define ll long long

using namespace std;
using namespace seal;
using namespace cv;

vector<string> file_names;

ll dev_con(ll params, ll pows)
{
    if (pows == 0)
        return 1;

    if ((pows & 1) == 1)
        return params * dev_con(params, pows - 1);

    ll T1 = dev_con(params, pows >> 1);

    return T1 * T1;
}


void get_file()
{
    filesystem::directory_iterator itr(filesystem::current_path() / "temp");

    ll cnt = 1;

    while (itr != filesystem::end(itr))
    {
        const filesystem::directory_entry& ety = *itr;
        string tmp = itr->path().string();

        while (tmp.back() != '\\')
            tmp.pop_back();

        tmp += (to_string(cnt)) + ".png";

        file_names.push_back(tmp);

        cnt++;
        itr++;
    }
}

void get_frame_pixel_sub(vector<double>& params1, vector<double>& params2, const Mat& img1, const Mat& img2, ll row, ll col)
{
    for (ll i = row; i < row + 10; i++)
    {
        for (ll j = col; j < col + 10; j++)
        {
            ll b1 = (ll)img1.at<Vec3b>(i, j)[0];
            ll g1 = (ll)img1.at<Vec3b>(i, j)[1];
            ll r1 = (ll)img1.at<Vec3b>(i, j)[2];

            ll b2 = (ll)img2.at<Vec3b>(i, j)[0];
            ll g2 = (ll)img2.at<Vec3b>(i, j)[1];
            ll r2 = (ll)img2.at<Vec3b>(i, j)[2];

            if (r1 != 0 && r2 != 0)
            {
                params1.push_back(r1);
                params2.push_back(r2);
            }
            if (g1 != 0 && g2 != 0)
            {
                params1.push_back(g1);
                params2.push_back(g2);
            }
            if (b1 != 0 && b2 != 0)
            {
                params1.push_back(b1);
                params2.push_back(b2);
            }
        }
    }
}

void get_frame_pixel_total(vector<double>& a, vector<double>& b, string S1, string S2)
{
    Mat img1 = imread(S1), img2 = imread(S2);

    get_frame_pixel_sub(a, b, img1, img2, 286, 654);

    get_frame_pixel_sub(a, b, img1, img2, 570, 741);

    get_frame_pixel_sub(a, b, img1, img2, 875, 719);
}

double addi(CKKSEncoder& encoder, Encryptor& encryptor, Decryptor& decryptor, Evaluator& evaluator, ll& scale, vector<double> v_tmp)
{
    double lo = 0, hi = 4500.000;

    while (lo + 0.0001 < hi)
    {
        vector<double> mid = { (lo + hi) / 2 };

        Plaintext pt_mid; Ciphertext ct_mid;

        encoder.encode(mid, scale, pt_mid);

        encryptor.encrypt(pt_mid, ct_mid);

        Ciphertext ct_check;

        evaluator.multiply(ct_mid, ct_mid, ct_check);

        // *********************************************************
        // this block is progressed by client
        {
            Plaintext pt_check; // 인코딩( |a| |b| )
            decryptor.decrypt(ct_check, pt_check);

            vector<double> vd_check;
            encoder.decode(pt_check, vd_check);

            if (v_tmp[0] < vd_check[0])
                hi = mid[0];
            else
                lo = mid[0];
        }
        // this block is progressed by client
        // *********************************************************
    }

    return lo;
}

// 벡터를 내적한 결과에 대한 암호화 값과, 벡터의 크기를 곱한 값을 암호화한 결과를 미리 저장해둡니다.
void solve(ll params)
{
    vector<double> bef, aft;

    get_frame_pixel_total(bef, aft, file_names[params], file_names[params + 1]);

    //////////////////////////////////////////////////////////////////////////////////////////////////////

    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 20, 20, 40 })); // set parameters

    shared_ptr<SEALContext> mid_term = SEALContext::Create(parms);
    ll scale = dev_con(2, 20);

    // 1. 구하고자 하는 실수치의 범위에 맞도록 매개변수를 설정합니다.
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    CKKSEncoder encoder(mid_term);

    vector<Plaintext> w_pts, i_pts;

    for (auto val : bef)
    {
        Plaintext p;
        encoder.encode(val, scale, p);
        i_pts.emplace_back(move(p));
    }

    for (auto val : aft)
    {
        Plaintext p;
        encoder.encode(val, scale, p);
        w_pts.emplace_back(p);
    }

    // 2. 평문 벡터를 패킹(인코딩) 합니다. 평문 벡터를 미리 패킹해야 암호화가 가능합니다.
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    PublicKey pk; SecretKey sk;

    KeyGenerator keygen(mid_term);
    sk = keygen.secret_key();
    pk = keygen.public_key();

    Encryptor encryptor(mid_term, pk);

    // 3. 공개키/비밀키 및 암/복호화 모듈, Encryptor를 생성합니다.
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    vector<Ciphertext> i_cts, i_cts_sz, w_cts_sz;
    
    Evaluator evaluator(mid_term);

    for (const auto& val : i_pts)
    {
        Ciphertext c1, c2;
        encryptor.encrypt(val, c1);
        encryptor.encrypt(val, c2);

        evaluator.multiply_inplace(c2, c2);

        i_cts.emplace_back(move(c1));
        i_cts_sz.emplace_back(move(c2));
    }

    for (const auto& val : w_pts)
    {
        Ciphertext c;
        encryptor.encrypt(val, c);

        evaluator.multiply_inplace(c, c);
     
        w_cts_sz.emplace_back(move(c));
    }

    // 4. 유클리드 거리를 계산하기 위해 사전 작업이 필요합니다. 
    //    CKKS에는 제곱근 계산이 불가능합니다. 따라서 우선 모든 벡터 원소를 제곱한 결과를 벡터에 저장합니다.
    /////////////////////////////////////////////////////////////////////////////////////////////////////

    for (ll i = 0; i < (ll)i_cts.size(); i++)
    {
        evaluator.multiply_plain_inplace(i_cts[i], w_pts[i]);
        evaluator.rescale_to_next_inplace(i_cts[i]);
    }

    Ciphertext ct_result_top;
    Ciphertext fin1, fin2, ct_result_bottom;

    evaluator.add_many(i_cts, ct_result_top);
    evaluator.add_many(i_cts_sz, fin1);
    evaluator.add_many(w_cts_sz, fin2);

    // 5. 벡터의 내적(dot product)을 암호화된 상태에서 구합니다. 또한, 두 벡터의 유클리드 거리의 제곱 또한 암호화된 상태에서 구합니다.
    //    이로써 ct_result_top은 cosP의 분자가 됩니다. 
    ///////////////////////////////////////////////////////////////////////////////////////

    Decryptor decryptor(mid_term, sk);

    Plaintext p_tmp_1, p_tmp_2;

    decryptor.decrypt(fin1, p_tmp_1);
    decryptor.decrypt(fin2, p_tmp_2);

    vector<double> v_tmp_1, v_tmp_2;

    encoder.decode(p_tmp_1, v_tmp_1);
    encoder.decode(p_tmp_2, v_tmp_2);

    // 7. 클라이언트는 비밀키를 갖고 유클리드 거리의 제곱된 결과를 얻습니다.
    ///////////////////////////////////////////////////////////////////////////////////////

    double ans1 = addi(encoder, encryptor, decryptor, evaluator, scale, v_tmp_1);

    double ans2 = addi(encoder, encryptor, decryptor, evaluator, scale, v_tmp_2);

    // 8. 서버와 클라이언트가 서로 통신하면서 실 제곱근을 찾습니다. 이 때 이분 탐색을 사용합니다. 이분 탐색의 매개변수를 제외한 모든 데이터는 완전히 배제한 상태에서 통신합니다.
    ///////////////////////////////////////////////////////////////////////////////////////

    Plaintext p1, p2; Ciphertext c1, c2;

    encoder.encode(vector<double>{ans1}, scale, p1);
    encoder.encode(vector<double>{ans2}, scale, p2);

    encryptor.encrypt(p1, c1);
    encryptor.encrypt(p2, c2);

    evaluator.multiply(c1, c2, ct_result_bottom);

    // 9. 실 제곱근 두 개를 다시 암호화 한 후, 곱해줍니다. 
    //    이로써 ct_result_bottom은 cosP의 분모가 됩니다. 
    //////////////////////////////////////////////////////////////////////////////////

    Plaintext pt_result_top;

    decryptor.decrypt(ct_result_top, pt_result_top);

    vector<double> vec_result_top;

    encoder.decode(pt_result_top, vec_result_top);

    // 10. 클라이언트는 분자를 복호화한 값을 저장합니다. 
    //////////////////////////////////////////////////////////////////////////////////

    double lo = 0.0, hi = 1.0;

    while (lo + 0.0001 < hi)
    {
        vector<double> mid = { (lo + hi) / 2 };

        Plaintext p; Ciphertext ct_inter;

        encoder.encode(mid, scale, p);

        encryptor.encrypt(p, ct_inter);

        Ciphertext ct_mid;

        evaluator.multiply(ct_result_bottom, ct_inter, ct_mid);

        // *********************************************************
        // this block is progressed by client
        {
            Plaintext pt_mid; // 인코딩( |a| |b| )
            decryptor.decrypt(ct_mid, pt_mid);

            vector<double> vd_mid;
            encoder.decode(pt_mid, vd_mid);

            if (vec_result_top[0] < vd_mid[0])
                hi = mid[0];
            else
                lo = mid[0];
        }
        // this block is progressed by client
        // *********************************************************
    }

    // 11. CKKS에서는 나눗셈 연산이 불가능합니다.
    //     따라서 이분 탐색을 통해 실제 코사인 값을 구합니다.
    //     서버와 클라이언트가 서로 통신하면서 실제 코사인 값을 찾습니다. 
    //     이분 탐색의 매개변수(lo, hi)를 제외한 모든 데이터는 완전히 배제한 상태에서 통신합니다.
    //////////////////////////////////////////////////////////////////////////////////

    cout << lo << '\n'; 

    // 12. 최종적으로 나온 코사인 값을 출력합니다.
}
// 현재 main 함수가 곧 클라이언트입니다.
int main()
{
    get_file();

    solve(0);

    exit(0);

    get_file();
    // 1. 파일을 받아옵니다.

    cout << "start comparison between two adjecent frames..." << '\n' << '\n';

    cout << "-----------------------------------------------------------------------------------------------" << '\n' << '\n';

    for (ll i = 0; i < (ll)file_names.size() - 1; i++)
    {
        cout << "frame " << i << ", " << "frame " << i + 1 << '\n';

        // 1. 내적 값에 대한 결과를 저장해야한다.
        // 2. 벡터의 크기를 곱한 값에 대한 암호화를 저장해야 한다. (미리!!)

        solve(i);

        cout << '\n' << '\n';

        cout << '\n' << '\n' << "-----------------------------------------------------------------------------------------------" << '\n' << '\n';
    }
}