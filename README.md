# 프로젝트 이름

# 뷰캠프

이미지 분석을 통해 이미지에 맞는 캠핑장을 추천해주는 서비스입니다. <br>
편리한 캠핑장 예약으로 국내 캠핑시장 활성화, 사이트 이용자 유치에 큰 도움이 될것입니다.<br>
시연 영상 : <br>
노션 페이지 : <br>
<br>

## 1. 제작 기간 , 참여 인원

- 2024.03.05~2024.03.27
- 4명
  <br>

## 2. 사용 기술

- Back-end: java17, Spring Boot 3.2.3, Spring web MVC, Spring data JPA, jwt, MySQL, Thymleaf 3.1.0

- Front-end: HTML 5, CSS3, JavaScript, Jquery, React, Redux, Redux-toolkit

  <br>

## 3. 주요 기능

- 이 프로젝트는 RESTful API를 이용해서 만들었습니다.

- 메인 페이지 - 일반 검색, 이미지 검색, 핫 아이템 섹션, 캠핑장 추천 유튜브
- 캠핑장 검색 페이지 - 카카오지도, 캠핑장 목록 검색
- 쇼핑몰 - 상품 페이지, 리뷰와 QNA 모달, 장바구니 담기, 바로구매기능
- 공지사항 - 공지사항 게시판
- 장바구니 - 장바구니에 담은 목록 확인과 장바구니 물건 구매
- 챗봇 - 원하는 페이지로 이동과 상품 검색 기능
- 로그인,회원가입 페이지 - 로그인과 회원가입
  <br>

## 4. 분석 패키지 구조도

![구조도](https://github.com/ljwc6020/camp/blob/main/%EA%B5%AC%EC%A1%B0%EB%8F%84.PNG)

<br>

## 5. 개체-관계 모델(ERD)

![ERD](https://github.com/ljwc6020/camp/blob/main/ERD.PNG)

<br>

## 6. 개발 팀 소개

- 이재우(깃헙 : https://github.com/ljwc6020 ) : 캠핑장 정보를 받는 고캠핑 api, 공지사항 백단, 페이징 처리 DTO, 상품 리뷰 이미지 처리, 챗봇, 챗봇 모달, 캠핑장 목록, 카카오지도, 메인 페이지 검색기능
- 임형욱(깃헙 : https://github.com/limhyeonguk ): 쇼핑몰 백단 , 상품 QNA 백단, 장바구니, QNA 페이지 백-프론트 연결, 장바구니 백-프론트 연결, 토스 api
- 신승훈(깃헙 : https://github.com/overguy723 ) : 쇼핑몰 페이지 백엔드 연동, 리뷰 페이지 백엔드 연동, QNA 페이지 백엔드 연동, 공지사항 페이지 백엔드 연동, react-router로 전체 페이지 spa로 연결, 쇼핑몰 인터페이스 css 구성, 리뷰 인터페이스 별점기능 css 구현,QNA 인터페이스 css 구현, 장바구니 상태 redux-toolkit으로 관리 공지사항 인터페이스 구성
- 최혜선(깃헙 : https://github.com/choihyeseon1217 ) : Security /JWT 회원 CRUD 구현, 임시 비밀번호 발송, 카카오 로그인, 권한 설정, 이미지 검색(Tensorflow), 회원가입 로그인 페이지 구현, 이미지 검색 페이지 구현

<br>

## 주의사항

- 저작권 문제로 이미지는 전부 삭제했습니다. 또한 개인정보가 들어간 서비스키 같은 데이터는 전부 지웠습니다.
