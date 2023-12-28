# 2023_Individual_Research_PET
2023년 개별연구 - PET 연구 :
동형암호를 이용한 코사인 값 계산 

동국대학교 컴퓨터공학전공 2018111999 심재혁

----------------------------

### 프로젝트 개요
- 현존하는 동형암호에는 나눗셈, 제곱근 계산이 없습니다.
- 클라이언트에서는 암호, 복호화만 허용하고 서버에서는 암호화된 결과에 대한 계산, 실 데이터와는 무관한 계산만 허용하므로, 아직까지는 활용 범위가 넓지 않습니다.
- 동형암호의 성질을 헤치지 않고 나눗셈, 제곱근 계산을 구현하였습니다. 이 때 이분 탐색을 사용합니다.
- 최종적으로 나눗셈과 제곱근 계산을 토대로 코사인 값을 계산합니다.

----------------------------

### 개발 환경
<p>
  <img src = "https://img.shields.io/badge/logo-C++ 17-pink?logo=cplusplus">
</p>

### 라이선스
 <img src = "https://img.shields.io/badge/license-MIT-orange">

### 사용 오픈소스
Microsoft SEAL : https://github.com/microsoft/seal

Opencv (C++) : https://github.com/opencv/opencv

----------------------------

### 프로젝트 로직
 <img src= https://github.com/hiwg08/2023_Individual_Research_PET/assets/91325459/1bb81efa-e595-482a-b615-2a5742be5cb3>
<div align="center">[시스템 구조도]</div>

<br/>

1. 클라이언트에서 두 개의 벡터 $\vec{A}$, $\vec{B}$를 소유합니다. 두 벡터의 크기(차원)는 동일하다고 가정합니다.
2. 클라이언트는 서버로 $\vec{A}$, $\vec{B}$를 암호화한 결과, $\vec{E(A)}$, $\vec{E(B)}$를 송신합니다.
3. 서버는 $\vec{E(A)}$, $\vec{E(B)}$에서 동형암호 연산을 통해 $|\vec{E(A)}|^2$, $|\vec{E(B)}|^2$를 계산합니다.
4. 이분 탐색을 통해 ${E(x)}^2 = |\vec{E(A)}|^2$, ${E(y)}^2 = |\vec{E(B)}|^2$를 만족하는 $x$, $y$를 구합니다.
   - 해당 과정에서 서버와 클라이언트 간 지속적인 통신을 합니다.
   - 서버는 암호화된 결과에 대한 계산 및 이분 탐색에서의 매개 변수 범위 계산만, 클라이언트는 암호화된 결과를 암호화, 복호화하는 것만 수행합니다.
5. 구해진 $x$, $y$를 토대로 다음과 같은 과정을 진행합니다.
   - 클라이언트에서 $x$, $y$를 $E(x)$, $E(y)$로 암호화합니다.
   - 동형암호 성질에 의해, $E(x)$는 $|\vec{E(A)}|$, $E(y)$는 $|\vec{E(B)}|$를 만족합니다.
   - 이 둘을 곱한 값, $|\vec{E(A)}||\vec{E(B)}|$를 얻습니다.
6. 서버에서 3번 과정 후 얻어진 $\vec{E(A)}$, $\vec{E(B)}$에서 $\vec{E(A)}\bullet \vec{E(B)}$를 얻습니다.
7. 이분 탐색을 통해 $E(x)|\vec{E(A)}||\vec{E(B)}| = \vec{E(A)}\bullet \vec{E(B)}$를 만족하는 $x$를 구합니다.
8. $x$가 곧 두 벡터의 코사인 값입니다.

----------------------------

### 실행 방법
> **(사용 환경은 반드시 visual studio 2019 버전으로 하셔야 합니다.)**
1. cmd 열기 ➜ 원하는 폴더에 "git clone https://github.com/hiwg08/2023_Individual_Research_PET.git" 입력
2. 폴더 열기 ➜ SEAL 폴더 열기 ➜ SEAL.sln 열기
3. 열면 get_cos, IR_PET, SEAL 프로젝트가 있습니다. 이 중 SEAL 프로젝트를 **release / x64** 모드로 먼저 빌드합니다. (IR_PET은 저의 별도의 프로젝트이므로 무시하셔도 됩니다.)
4. get_cos 프로젝트를 **release / x64** 모드로 빌드하고 실행하면 됩니다. 

----------------------------

### 실행 결과
> 3차원 벡터로 시도했을 때

<img src = 'https://github.com/hiwg08/2023_Individual_Research_PET/assets/91325459/1acf270e-9367-4e75-be54-bd3ea4fcf050'>
<br>
➜ 상대 오차 : 0.0001705
<br><br><br> 

> 5차원 벡터로 시도했을 때

<img src = 'https://github.com/hiwg08/2023_Individual_Research_PET/assets/91325459/78c3cb43-da3e-49ee-8819-86653c9c4dc1'>
<br>
➜ 상대 오차 : 0.0000323

<br><br>

- 기타 다른 차원, 다른 원소들을 입력으로 넣어도 오차는 상당히 적습니다.
- CKKS 특성 상, 상대 오차는 반드시 나옵니다.
- 현재 이분 탐색의 경계 범위를 0.0001로 설정하였으나 (main.cpp의 29번째 줄 - while(lo + **0.0001**) < hi 부분), 이는 임의로 넣은 것이며, 정확한 경계 범위 설정에 대해서 논의가 필요합니다.
----------------------------

### 기대 효과
- 동형암호의 퍼포먼스가 향상된다면, 실제 동형암호의 나눗셈과 제곱근 계산 적용에 대한 추가적인 논의가 활발하게 이루어질 것으로 사료됩니다.
- 지하철 CCTV 처럼, 개인정보 문제가 많은 곳에 해당 프로젝트를 적용한다면 보안 이슈 없이 문제를 해결할 수 있게 됩니다.

----------------------------
### 한계점
- 퍼포먼스 측면에서 많은 개선이 필요합니다.
- 이분 탐색 시의 경계 범위와 SEAL에서 설정하는 매개변수 값을 낮게 잡을 시, 퍼포먼스는 증가하나 결과의 정밀도는 감소하는 불가피한 Trade-Off가 형성됩니다.