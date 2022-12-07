## :earth_asia: 우리사이클린 프로젝트

-  우리사이클린 프로젝트에서 백앤드를 담당했으며 reward 기능과 map 기능을 구현하였습니다.

-  해당 파일은 회원가입, 게시판 기능에 reward와 map 기능을 merge한 파일입니다.

:link:프로젝트 organization-repository링크 
:https://github.com/separate-the-trash/capstone_project

## :heavy_check_mark: reward 기능 
-  분리수거시 포인트 50씩 추가되고 기프티콘으로 교환 가능 

-  기프티콘의 교환하기 버튼을 누르면  ' 교환 되었습니다' 라고 알람이 뜨고 포인트가 부족하면 ' 포인트가 부족합닌다' 라는 알람이 뜨고 기프티콘의 금액만큼 포인트가 차감됨

-  실제 기프티콘으로는 아직 교환 불가함. 현재는 포인트 적립과 사용, 사용시 메세지 뜨기 기능만 구현되어있음.

   (추후에 배포까지 진행된다면 구글 애드샌스 수익으로 교환 가능할 예정)
              
## :heavy_check_mark: map 기능

- 서울시 공공데이터< 가로 휴지통 위치 정보> 를 바탕으로 구글 api를 사용하여 마크를 찍어줌.

- 제공되는 공공데이터는 도로명 주소만 제공되어서 지오코딩을 통해 위도, 경도 좌표로 변환하고 이후 json 으로 변환하여 id와 함께 프론트에 넘겨줌.
             
          
<img width="306" alt="KakaoTalk_20221121_200311480" src="https://user-images.githubusercontent.com/74054487/206088680-f40b5218-d6c6-4de7-8ecd-9528fe15c038.png">

