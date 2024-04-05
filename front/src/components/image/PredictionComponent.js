import React, { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom"; // URL 파라미터를 읽기 위해 사용
import { getInform } from "../../api/imageApi"; // 위에서 작성한 API 호출 함수를 임포트
import "../../styles/pages/predictionPage.scss";

function PredictionComponent() {
  const [data, setData] = useState([]); // 서버로부터 받은 데이터를 저장할 상태
  const { prediction } = useParams(); // URL 파라미터에서 prediction 값을 읽어옴
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const result = await getInform(prediction); // API 호출
        setData(result); // 받아온 데이터를 상태에 저장
      } catch (error) {
        console.error("Failed to fetch data:", error);
      }
    };

    fetchData();
  }, [prediction]); // prediction 값이 변경될 때마다 fetchData 함수를 다시 호출

  const handleClickBack = () => {
    navigate("/");
  };

  // 조건에 따라 URL을 결정하는 로직
  const mapUrl =
    prediction === "mountain"
      ? "https://map.kakao.com/?q=%EA%B2%BD%EA%B8%B0%20%EB%8F%99%EB%91%90%EC%B2%9C%EC%8B%9C%20%EC%95%88%ED%9D%A5%EB%A1%9C%2065-42"
      : prediction === "sea"
      ? "https://map.kakao.com/?q=%EA%B2%BD%EB%82%A8%20%EA%B1%B0%EC%A0%9C%EC%8B%9C%20%EA%B1%B0%EC%A0%9C%EB%A9%B4%20%EC%86%8C%EB%9E%91%EB%A6%AC%20176-4"
      : "";

  return (
    <div className="prediction-container">
      <h3 className="prediction-title">
        <strong>유사한 캠핑장 정보</strong>
      </h3>
      <img src={`http://localhost:8080/${data.imagePath}`} alt={data.name} />

      <ul className="prediction-list">
        <a
          target="_blank"
          href={mapUrl}
          rel="noreferrer noopener"
          className="sc-jvLaUc cEAbrB"
        >
          <li>이름 : {data.name}</li>
        </a>

        <li>주소 : {data.address}</li>

        <li>전화번호 : {data.campPhone}</li>
      </ul>
      <button type="button" onClick={handleClickBack}>
        돌아가기
      </button>
    </div>
  );
}

export default PredictionComponent;
