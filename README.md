# 2023_Individual_Research_PET
2023년 개별연구 - PET 연구 :
동형암호를 이용한 코사인 값 계산 

동국대학교 컴퓨터공학전공 2018111999 심재혁

----------------------------

### 프로젝트 개요
- 현재 동형암호에는 나눗셈 계산, 제곱근 계산이 제공되지 않습니다.
- 이진 탐색을 활용하여, 나눗셈과 제곱근 계산을 수행합니다.
- 나눗셈과 제곱근 계산을 토대로 최종적으로 코사인 값을 계산합니다.

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
<div align="center">[플로우 차트]</div>

----------------------------

### 기대 효과
- 지하철 CCTV 처럼, 개인정보 노출에 관련하여 이슈가 많은 곳에 해당 프로젝트를 적용한다면 보안 이슈 없이 문제를 해결할 수 있게 됩니다.

----------------------------
### 한계점
- 퍼포먼스 측면에서 개선이 필요합니다.
- SEAL에서 설정하는 매개변수 값을 낮게 잡을 시, 퍼포먼스는 증가하나 결과인 실수치의 정밀도는 감소하는 불가피한 Trade-Off가 생깁니다.   
