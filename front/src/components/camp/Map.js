/*global kakao*/
import React, { useEffect, useRef } from "react";
import "../../styles/pages/campPage.scss";

const Map = ({ onDoubleClick, mapCoordinates }) => {
  const mapRef = useRef(null); // 지도 객체의 참조를 저장하기 위한 useRef
  const markers = useRef([]); // 마커들을 관리하기 위한 배열
  // useEfect를 두개로 나누어, 마커를 생성하는 것과, 더블 클릭으로 부모에게 위 경도 전달하는
  // 기능을 나눴습니다. 추가로 마커를 클릭하면 캠핑장 이름이 나옵니다.
  // 받아온 캠핑장 좌표(mapCoordinates 속 첫번째 좌표) 로 지도 화면을 이동시키기 위한 방법
  useEffect(() => {
    if (!mapRef.current || !mapCoordinates.length) return; // 이전과 동일하게 null 체크 돕니다
    // 맵을 참조해서 가져옵니다.
    const map = mapRef.current;
    // 배열의 첫번째 요소름 firstCampground 라는 이름에 담습니다.
    const firstCampground = mapCoordinates[0]; // 첫 번째 캠핑장 좌표 가져오기

    // 첫 번째 캠핑장 위치로 지도 이동, 카카오 api가 panTo 기능을 쓰면 해당 좌표로 이동합니다.
    map.panTo(
      new kakao.maps.LatLng(firstCampground.mapY, firstCampground.mapX)
    );
  }, [mapCoordinates]);
  useEffect(() => {
    // 맵이 비어있는지 체크, 안비어있다면 실행합니다.
    // 비어있다면 null 이라서 진행되지 않습니다.
    if (!mapRef.current) return;
    // 카카오 지도를 현재 ampRef에 저장된 객체를 쓰갰습니다.
    const map = mapRef.current;

    // 기존 마커들 제거, 제거하면서 infowindow창도 다 꺼버립니다.
    markers.current.forEach((item) => {
      item.marker.setMap(null);
      item.infowindow.close();
    });
    markers.current = [];
    // 이전과 동일한 마커정보를 입력하는 반복문입니다.
    mapCoordinates.forEach((coord) => {
      // mapCoordinates 에 위 경도를 가져와서 makerPositon에 담습니다.
      const markerPosition = new kakao.maps.LatLng(coord.mapY, coord.mapX);
      // 마커를 생성합니다. 위치는 우리가 markerPosition에 넣은거
      const marker = new kakao.maps.Marker({
        position: markerPosition,
      });
      // 여기가 정보창을 띄우는 법입니다. 클래스 이름은 .infowindow로 css 수정작업 가능하실겁니다.
      const infowindow = new kakao.maps.InfoWindow({
        // 내용은 coord, 즉 mapCoordinates 안에 name 입니다.
        // 수동으로 div 지정해주고 클래스 이름 줬습니다. 테스트해주세요
        content: `<div class="infowindow">${coord.name}</div>`,
      });
      // 클릭시 이벤트 추가입니다.
      kakao.maps.event.addListener(marker, "click", function () {
        // 마커를 클릭하여 정보 창을 열었을 때
        if (infowindow.getMap()) {
          // 이미 열려있는 경우 다시 클릭하면 정보 창을 닫음
          infowindow.close();
        } else {
          // 정보 창이 닫혀있는 경우 다시 클릭하면 정보 창을 엶
          infowindow.open(map, marker);
        }
      });
      // map 에 maker를 셋팅합니다. 즉 위에 정보들을 바탕으로 마커를 꼽습니다.
      marker.setMap(map);
      // 현재 마커 정보들, 마커 위치, 마커 정보를 makers에 넣어 최신화 합니다.
      markers.current.push({ marker, infowindow });
    });
  }, [mapCoordinates]);

  // 이 부분이 저희 원래 코드와 동일합니다.
  useEffect(() => {
    // 카카오 지도 객체 생성
    const container = document.getElementById("map");
    const options = {
      center: new kakao.maps.LatLng(37.365264512305174, 127.10676860117488),
      level: 10,
    };
    const map = new kakao.maps.Map(container, options);

    // 더블 클릭 이벤트 핸들러 등록
    const handleMapDoubleClick = (mouseEvent) => {
      var latlng = mouseEvent.latLng;
      var latitude = latlng.getLat();
      var longitude = latlng.getLng();
      // 더블 클릭 시 부모 컴포넌트로 위도, 경도 값과 함께 event 객체를 전달
      onDoubleClick(latitude, longitude, mouseEvent);
    };
    kakao.maps.event.addListener(map, "click", handleMapDoubleClick);

    // 지도 객체를 useRef를 통해 저장
    mapRef.current = map;

    // 컴포넌트가 언마운트될 때 이벤트 핸들러 제거
    return () => {
      kakao.maps.event.removeListener(map, "click", handleMapDoubleClick);
    };
  }, []); // 처음 렌더링 시에만 실행

  return (
    <div className="map-container">
      <div id="map"></div>
    </div>
  );
};

export default Map;
