import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import "../../styles/pages/campPage.scss";
import BasicLayout from "../../layouts/BasicLayout";
import Map from "../../components/camp/Map";
import Search from "../../components/camp/Search";
import CampList from "../../components/camp/CampList";

function CampPage() {
  const [pageNumList, setPageNumList] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [campgrounds, setCampgrounds] = useState([]); // 캠핑장 목록 상태 추가

  const [keyword, setKeyword] = useState("");

  // 부모 컴포넌트에서 상태 관리, 지도에서 위도 경도 뽑아오는거
  const [latitude, setLatitude] = useState(null);
  const [longitude, setLongitude] = useState(null);

  // Map 컴포넌트에서 전달받은 더블 클릭 이벤트 핸들러
  const handleMapDoubleClick = (lat, lng) => {
    setLatitude(lat);
    setLongitude(lng);
    console.log("받은 위도:", lat);
    console.log("받은 경도:", lng);
  };

  const [mapCoordinates, setMapCoordinates] = useState([]);

  const handleMapCoordinates = (coordinates) => {
    // 좌표 데이터를 받아와서 처리하는 로직을 구현합니다.
    console.log("Received map coordinates:", coordinates);
    setMapCoordinates(coordinates);
  };

  const handleSearch = (keyword) => {
    // 검색 버튼 클릭 시 호출되는 함수
    setKeyword(keyword); // setKeyword 함수를 호출하여 keyword 값을 설정
    console.log(keyword);
  };

  const handleKeywordReset = () => {
    // 검색 키워드 초기화 함수
    setKeyword("");
  };

  return (
    <BasicLayout>
      <div className="wrap">
        <div className="camping-wrap">
          <div className="map">
            <ul>
              <li>- 캠핑장 -</li>
              <li>지도에서 지역을 선택하고 캠핑장을 찾아보세요</li>
            </ul>
          </div>
          <div className="map-section">
            <Map
              onDoubleClick={handleMapDoubleClick}
              mapCoordinates={mapCoordinates}
            />
            <ul>
              <Search onSearch={handleSearch} />{" "}
              {/* 검색 컴포넌트에 검색 함수 전달 */}
              <CampList
                onMapCoordinates={handleMapCoordinates}
                keyw={keyword}
                latitude={latitude} // 위도를 자식 컴포넌트에 전달
                longitude={longitude} // 경도를 자식 컴포넌트에 전달
                // 캠핑장 목록을 자식 컴포넌트에 전달
                onKeywordReset={handleKeywordReset} // 검색 키워드 초기화 함수 전달
              />
              {/* 캠핑장 목록 전달 */}
              {/* 페이지 번호 클릭 시 다른 페이지로 이동하는 링크 */}
              {pageNumList.map((pageNum) => (
                <li key={pageNum}>
                  <Link to={`/page/${pageNum}`}>페이지 {pageNum}</Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </BasicLayout>
  );
}

export default CampPage;
