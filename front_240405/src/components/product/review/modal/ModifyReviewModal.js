import React, { useEffect, useRef, useState } from "react";
import {
  putReview,
  deleteReview,
  getReview,
} from "../../../../api/productReviewApi";
import { API_SERVER_HOST } from "../../../../api/userApi";
import LoadingModal from "../../../modal/LoadingModal";
import AlertModal from "../../../modal/AlertModal";
import { IoCloseOutline } from "react-icons/io5";
import useCustomLoginPage from "../../../../hooks/useCustomLoginPage";
import useStarRating from "../../../../hooks/useStarRating";
import StarRating from "../../../common/star/StarRating";
import "../../../../styles/components/modal/modifyModal.scss";

const initState = {
  reviewText: "",
  uploadFileNames: [],
};

const host = API_SERVER_HOST;

const ModifyReviewModal = ({
  prno,
  openModifyModal,
  closeModifyModal,
  reloadReviewList,
  reloadReviewRead,
}) => {
  const [review, setReview] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const uploadRef = useRef();
  const { isLogin, loginState } = useCustomLoginPage();
  const [rating, handleRating] = useStarRating();
  const [imagePreviewUrl, setImagePreviewUrl] = useState("");

  useEffect(() => {
    setLoading(true);
    getReview(prno).then((data) => {
      setReview(data);
      const convertedRating = convertScoreToRating(data.score);
      handleRating(convertedRating);
      setLoading(false);
    });
  }, [prno, handleRating]);

  const handleChangeReview = (e) => {
    setReview({
      ...review,
      [e.target.name]: e.target.value,
    });
  };

  const handleClickModify = () => {
    if (rating === 0) {
      alert("별점을 선택해주세요!");
      return;
    } else if (review.reviewText.trim() === "") {
      alert("리뷰 내용을 입력해주세요!");
      return;
    }
    const files = uploadRef.current.files;
    const formData = new FormData();

    for (let i = 0; i < files.length; i++) {
      formData.append("files", files[i]);
    }

    formData.append("reviewText", review.reviewText);
    formData.append("score", Math.round(rating * 2));
    formData.append("reviewer", review.reviewer);

    for (let i = 0; i < review.uploadFileNames.length; i++) {
      formData.append("uploadFileNames", review.uploadFileNames[i]);
    }

    setLoading(true);

    putReview(prno, formData).then((data) => {
      setResult("수정 완료");
      setLoading(false);
      reloadReviewList();
      reloadReviewRead();
    });
  };

  const handleClickDelete = () => {
    setLoading(true);
    const deleteReviewDTO = {
      prno: review.prno,
      reviewer: review.reviewer,
    };
    deleteReview(deleteReviewDTO).then((data) => {
      setResult("삭제 완료");
      setLoading(false);
    });
  };

  const handleImagePreview = (e) => {
    e.preventDefault();

    let reader = new FileReader();
    let file = e.target.files[0];

    reader.onloadend = () => {
      setImagePreviewUrl(reader.result);
    };

    if (file) {
      reader.readAsDataURL(file);
    }
  };

  const removeImages = (imageName) => {
    setReview((prevReview) => ({
      ...prevReview,
      uploadFileNames: prevReview.uploadFileNames.filter(
        (fileName) => fileName !== imageName
      ),
    }));
  };

  const closeAlertModal = () => {
    if (result === "수정 완료") {
      closeModifyModal();
    } else if (result === "삭제 완료") {
      reloadReviewList();
    }

    setResult(null);
  };

  const convertScoreToRating = (score) => {
    return score / 2;
  };

  return (
    <div
      className={`modal modifyModal ${openModifyModal ? "show" : ""}`}
      tabIndex="-1"
    >
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={`${result}`}
          content={"정상적으로 처리되었습니다."} //결과 모달창
          callbackFn={closeAlertModal}
        />
      ) : (
        <></>
      )}
      <div className="modifyReview-group">
        <div className="modifyReview-area">
          <div className="modifyReview-header">
            <div className="modifyReview-title">리뷰 수정</div>
            <button
              type="button"
              className="btn-close"
              onClick={closeModifyModal}
            >
              <IoCloseOutline />
            </button>
          </div>
          <div className="modifyReview-body">
            <div className="modifyReview-wrap">
              <div className="modifyReview-info">작성자</div>
              <div className="modifyReview-content reviewer">
                {loginState.email}
              </div>
            </div>
            <div className="modifyReview-wrap">
              <div className="modifyReview-info">별점</div>
              <StarRating rating={rating} onRatingChange={handleRating} />
            </div>
            <div className="modifyReview-wrap">
              <div className="modifyReview-info">리뷰 내용</div>
              <textarea
                className="modifyReview-content reviewText"
                name="reviewText"
                type={"text"}
                value={review.reviewText}
                onChange={handleChangeReview}
              />
            </div>
            <div className="modifyReview-wrap">
              <div className="modifyReview-info">현재 이미지</div>
              <div className="modifyReview-box currentImg">
                <div className="modifyReview-content">
                  {review.uploadFileNames.map((imgFile, i) => (
                    <div className="imageContainer" key={i}>
                      <img alt="img" src={`${host}/review/view/s_${imgFile}`} />
                      <button onClick={() => removeImages(imgFile)}>X</button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            {/* 이미지 미리보기 표시 */}
            <div className="modifyReview-wrap">
              <div className="modifyReview-info">이미지 추가</div>
              <div className="modifyReview-box newImg">
                <div className="imgContainer">
                  {imagePreviewUrl ? (
                    <img
                      src={imagePreviewUrl}
                      alt="리뷰 이미지"
                      className="modifyReviewImage"
                    />
                  ) : (
                    <label htmlFor="uploadReviewImage">파일 선택</label>
                  )}
                  <input
                    ref={uploadRef}
                    id="uploadReviewImage"
                    type="file"
                    multiple={true}
                    onChange={handleImagePreview}
                  />
                </div>
              </div>
            </div>
          </div>
          <div className="modifyReview-footer">
            <button
              type="button"
              className="modifyReview-modifyBtn"
              onClick={handleClickModify}
            >
              수정
            </button>
            <button
              type="button"
              className="modifyReview-deleteBtn"
              onClick={handleClickDelete}
            >
              삭제
            </button>
            <button
              type="button"
              className="modifyReview-closeBtn"
              onClick={closeModifyModal}
            >
              닫기
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModifyReviewModal;
