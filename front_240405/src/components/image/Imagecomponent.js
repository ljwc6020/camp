import React, { useState, useEffect } from "react";
import * as mobilenet from "@tensorflow-models/mobilenet";
import "@tensorflow/tfjs";
import { useNavigate } from "react-router-dom";
import Loader from "./Loader";
import "../../styles/components/imageComponent.scss";
import { IoCloudUploadOutline } from "react-icons/io5";
import styled from "styled-components";

function ImageClassifier() {
  const [imageURL, setImageURL] = useState("");
  const [predictions, setPredictions] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [prediction, setPrediction] = useState(""); // 최종 분류 결과 상태

  let navigate = useNavigate();

  function handleClick() {
    navigate(`/${prediction}`);
  }

  useEffect(() => {
    const classifyImage = async () => {
      if (imageURL) {
        setIsAnalyzing(true);
        const img = document.getElementById("uploaded-image");
        const model = await mobilenet.load();
        const results = await model.classify(img);
        const predictionsInPercent = results.map((result) => ({
          className: result.className,
          probability: (result.probability * 100).toFixed(2) + "%",
        }));
        setPredictions(predictionsInPercent);

        // 최고 확률을 가진 예측 결과를 기반으로 최종 분류 레이블 설정
        const highestPrediction = predictionsInPercent[0];
        let finalPrediction = "인식할 수 없음"; // 기본값
        if (
          highestPrediction.className.toLowerCase().includes("mountain") ||
          highestPrediction.className.toLowerCase().includes("hill") ||
          highestPrediction.className.toLowerCase().includes("peak") ||
          highestPrediction.className.toLowerCase().includes("volcano")
        ) {
          finalPrediction = "mountain";
        } else if (
          highestPrediction.className.toLowerCase().includes("sea") ||
          highestPrediction.className.toLowerCase().includes("ocean")
        ) {
          finalPrediction = "sea";
        }
        setPrediction(finalPrediction); // 최종 분류 결과 상태 업데이트

        setIsAnalyzing(false);
      }
    };

    classifyImage();
  }, [imageURL]);

  const handleImageUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const url = URL.createObjectURL(file);
      setImageURL(url);
    }
  };

  return (
    <div className="img-search-wrap">
      <input
        id="img-search"
        type="file"
        onChange={handleImageUpload}
        accept="image/*"
      />
      {imageURL ? (
        <img
          id="uploaded-image"
          src={imageURL}
          alt="Upload Preview"
          crossOrigin="anonymous"
        />
      ) : (
        <label htmlFor="img-search">
          <UploadIcon>
            <IoCloudUploadOutline className="logo" />
            <>이미지로 캠핑장 찾기</>
          </UploadIcon>
        </label>
      )}
      {isAnalyzing ? (
        <div className="img-search-loader">
          <Loader />
        </div>
      ) : (
        <div className="img-search-prediction">
          {prediction && (
            <p>
              <strong>유사한 캠핑장 보기</strong>
              <button type="button" onClick={handleClick}>
                click
              </button>
            </p>
          )}
          {/* {predictions.length > 0 && (
            <div>
              <h5>모든 분류 결과:</h5>
              <ul>
                {predictions.map((pred, index) => (
                  <li key={index}>
                    {pred.className}: {pred.probability}
                  </li>
                ))}
              </ul>
            </div>
          )} */}
        </div>
      )}
    </div>
  );
}

const UploadIcon = styled.div`
  .logo {
    width: 30px;
    height: 30px;
    margin-right: 4px;
    color: #fff;
  }
`;

export default ImageClassifier;
