import React, { useState } from "react";
import "../../styles/pages/campPage.scss";

const Search = ({ onSearch }) => {
  const [keyword, setKeyword] = useState(""); // 키워드 상태 초기화

  const handleSearch = () => {
    // 검색 버튼 클릭 시 검색 함수 호출
    onSearch(keyword);
  };

  const handleKeyPress = (e) => {
    // 엔터 키를 눌렀을 때 검색 함수 호출
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  return (
    <li>
      <input
        type="text"
        className="camp-input"
        placeholder="원하는 지역을 입력하세요"
        value={keyword}
        onChange={(e) => setKeyword(e.target.value)}
        onKeyPress={handleKeyPress} // 엔터 키 이벤트 핸들러 추가
      />
      <button onClick={handleSearch} className="camp-btn">
        검색
      </button>
    </li>
  );
};

export default Search;
