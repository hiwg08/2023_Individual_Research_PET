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


// 벡터를 내적한 결과에 대한 암호화 값과, 벡터의 크기를 곱한 값을 암호화한 결과를 미리 저장해둡니다.
void solve(ll params)
{
    vector<double> bef, aft;

    get_frame_pixel_total(bef, aft, file_names[params], file_names[params + 1]);

    vector<double> sz_bef = { 0 }, sz_aft = { 0 };

    for (ll i = 0; i < (ll)bef.size(); i++)
    {
        sz_aft[0] += aft[i] * aft[i];
        sz_bef[0] += bef[i] * bef[i];
    }

    sz_bef[0] = sqrt(sz_bef[0]);
    sz_aft[0] = sqrt(sz_aft[0]);

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, 25, 25, 25, 25, 35 })); // set parameters

    shared_ptr<SEALContext> mid_term = SEALContext::Create(parms);
    ll scale = dev_con(2, 30);
    //
    ///// ////////////////////////////////////////////////////////////////////////////////////////////////

    CKKSEncoder encoder(mid_term);

    vector<Plaintext> w_pts, i_pts;

    for (auto val : bef)
    {
        Plaintext p;

        encoder.encode(val, scale, p);
        i_pts.emplace_back(move(p));
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////

    PublicKey pk; SecretKey sk;

    KeyGenerator keygen(mid_term);
    sk = keygen.secret_key();
    pk = keygen.public_key();

    Encryptor encryptor(mid_term, pk);

    /////////////////////////////////////////////////////////////////////////////////////////////////////

    vector<Ciphertext> cts, cts_sz;

    for (const auto& val : i_pts)
    {
        Ciphertext c;
        encryptor.encrypt(val, c);
        cts.emplace_back(move(c));
    }

    for (auto val : aft)
    {
        Plaintext p;
        encoder.encode(val, scale, p);
        w_pts.emplace_back(p);
    }

    Evaluator evaluator(mid_term);

    for (ll i = 0; i < (ll)cts.size(); i++)
    {
        evaluator.multiply_plain_inplace(cts[i], w_pts[i]);
        evaluator.rescale_to_next_inplace(cts[i]);
    }

    Plaintext p1, p2; Ciphertext c1, c2;

    encoder.encode(sz_bef, scale, p1);

    encryptor.encrypt(p1, c1);

    encoder.encode(sz_aft, scale, p2);

    encryptor.encrypt(p2, c2);

    Ciphertext ct_result_scalar;
    evaluator.multiply(c1, c2, ct_result_scalar);

    Decryptor decryptor(mid_term, sk);

    Ciphertext ct_result_dot;
    evaluator.add_many(cts, ct_result_dot);

    Plaintext pt_result_dot;
    decryptor.decrypt(ct_result_dot, pt_result_dot);

    vector<double> vec_result_dot;
    encoder.decode(pt_result_dot, vec_result_dot);

    Plaintext pt_result_scalar;
    decryptor.decrypt(ct_result_scalar, pt_result_scalar);

    vector<double> vec_result_scalar;
    encoder.decode(pt_result_scalar, vec_result_scalar);

    ////////////////////////////////////////////////////////////////////////////////

    double lo = 0.0, hi = 1.0;

    while (lo + 0.001 < hi) // ct_result_scalar * new
    {
        vector<double> mid = { (lo + hi) / 2 };

        Plaintext p; Ciphertext ct_inter;

        encoder.encode(mid, scale, p);

        encryptor.encrypt(p, ct_inter);

        Ciphertext ct_mid;

        evaluator.multiply(ct_result_scalar, ct_inter, ct_mid);

        ////////////////////////////////////////////////////////////// this block is progressed by client
        {
            Plaintext pt_mid; // 인코딩( |a| |b| )
            decryptor.decrypt(ct_mid, pt_mid);

            vector<double> vd_mid;
            encoder.decode(pt_mid, vd_mid);

            if (vec_result_dot[0] < vd_mid[0])
                hi = mid[0];
            else
                lo = mid[0];
        }
    }

    cout << lo << '\n';
}
// 현재 main 함수가 곧 클라이언트입니다.
int main()
{
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