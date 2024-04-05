import React, { useEffect, useState } from "react";
import {
  getBasedList,
  getLocationList,
  getSearchList,
} from "../../api/campApi";
import { Link, useLocation } from "react-router-dom";

const initState = {
  items: [],
  pageNo: [],
};

const CampList = ({
  latitude,
  longitude,
  keyw,
  onMapCoordinates,
  onKeywordReset,
}) => {
  const [serverData, setServerData] = useState([]);
  const [pageNo, setPageNo] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1); // 현재 페이지 번호 상태 추가
  const [loading, setLoading] = useState(false); // 'loading' 상태 추가 및 useState를 사용하여 정의

  const location = useLocation();
  // url이 변경될때만 실행, 메인에서 받아온 값을 keyw에 넣음
  // 이후 우리 컴포넌트에서 keyw가 변경되면 알아서 url에서 얻은 값이 아니라
  // 우리가 검색한 값이 keyw 가됨
  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const urlKeyword = searchParams.get("keyword");
    if (urlKeyword) {
      keyw = urlKeyword;
    }
  }, [location]);

  useEffect(() => {
    // 키워드가 변경되면 페이지를 1로 설정

    setPageNo(1);
    setCurrentPage(1); // 현재 페이지 번호도 초기화
  }, [keyw]);

  useEffect(() => {
    // 위도와 경도 값이 변경되면 키워드 초기화 및 페이지를 1로 설정
    if (latitude !== null && longitude !== null) {
      keyw = null;
      onKeywordReset();
      setPageNo(1);
      setCurrentPage(1); // 현재 페이지 번호도 초기화
    }
  }, [latitude, longitude]);
  // 기존과 동일
  const callApiBasedOnCondition = () => {
    setLoading(true);
    if (keyw) {
      getSearchList(pageNo, keyw).then((data) => {
        const items = data.response.body.items?.item || [];
        const count = data.response.body.totalCount;
        setServerData(items);
        setTotalCount(count);
        setLoading(false);
      });
    } else if (latitude && longitude) {
      getLocationList(pageNo, longitude, latitude).then((data) => {
        const items = data.response.body.items?.item || [];
        const count = data.response.body.totalCount;
        setServerData(items);
        setTotalCount(count);
        setLoading(false);
      });
    } else {
      getBasedList(pageNo).then((data) => {
        const items = data.response.body.items?.item || [];
        const count = data.response.body.totalCount;
        setServerData(items);
        setTotalCount(count);
        setLoading(false);
      });
    }
  };

  const handlePageClick = (pageNumber) => {
    setPageNo(pageNumber);
    setCurrentPage(pageNumber); // 클릭한 페이지 번호로 현재 페이지 번호 업데이트
  };

  const handleNextPage = () => {
    const endPage = Math.min(Math.ceil(totalCount / 5));
    const nextPage = Math.min(pageNo + 5, endPage); // 다음 페이지 번호 계산
    setPageNo(nextPage); // 페이지 번호 업데이트
    setCurrentPage(nextPage); // 현재 페이지 번호 업데이트
  };

  const handlePrevPage = () => {
    const prevPageNo = Math.max(pageNo - 5, 1);
    setPageNo(prevPageNo); // 페이지 번호 업데이트
    setCurrentPage(prevPageNo); // 현재 페이지 번호 업데이트
  };

  useEffect(() => {
    callApiBasedOnCondition();
  }, [pageNo, keyw, latitude, longitude]);

  useEffect(() => {
    if (serverData.length > 0) {
      const coordinates = serverData.map((item) => ({
        mapX: item.mapX,
        mapY: item.mapY,
        name: item.facltNm,
      }));
      onMapCoordinates(coordinates);
    }
  }, [serverData]);

  const startPage = Math.max(Math.floor((pageNo - 1) / 5) * 5 + 1, 1);
  const endPage = Math.min(startPage + 4, Math.ceil(totalCount / 5));

  return (
    <li>
      {loading && <div className="CampSpinner"></div>}{" "}
      {/* 로딩 중일 때 스피너 표시 */}
      {!loading && (
        <div>
          <div className="CampSite">
            {serverData.map((item) => (
              <Link to={item.homepage}>
                <div key={item.contentId} className="CampWrap">
                  <div className="flex">
                    <div className="CampName">{item.facltNm}</div>
                    <div className="CampAddress">{item.addr1}</div>
                    <div className="CampPhoto">
                      {item.firstImageUrl && (
                        <img src={item.firstImageUrl} alt="Thumbnail" />
                      )}
                    </div>
                  </div>
                </div>
              </Link>
            ))}
            {serverData.length === 0 && (
              <div className="EmptyMessage">캠핑장 정보가 없습니다.</div>
            )}
          </div>
          <div className="btn-section">
            <button onClick={handlePrevPage} className="prev">
              ◀
            </button>
            {Array.from({ length: endPage - startPage + 1 }, (_, index) => {
              const pageNumber = startPage + index;
              return (
                <button
                  key={pageNumber}
                  onClick={() => handlePageClick(pageNumber)}
                  className={
                    pageNumber === currentPage
                      ? "page-btn-highlighted"
                      : "page-btn"
                  }
                  disabled={pageNumber > Math.ceil(totalCount / 5)}
                >
                  {pageNumber}
                </button>
              );
            })}
            <button onClick={handleNextPage} className="next">
              ▶
            </button>
          </div>
        </div>
      )}
    </li>
  );
};

export default CampList;
