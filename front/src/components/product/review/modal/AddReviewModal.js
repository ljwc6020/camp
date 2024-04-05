import React, { useRef, useState } from "react";
import { postReview } from "../../../../api/productReviewApi";
import LoadingModal from "../../../modal/LoadingModal";
import AlertModal from "../../../modal/AlertModal";
import { IoCloseOutline } from "react-icons/io5";
import useCustomLoginPage from "../../../../hooks/useCustomLoginPage";
import useStarRating from "../../../../hooks/useStarRating";
import StarRating from "../../../common/star/StarRating";
import "../../../../styles/components/modal/addModal.scss";

const AddReviewModal = ({
  pno,
  openAddModal,
  closeAddModal,
  reloadReviewList,
}) => {
  const [review, setReview] = useState({ reviewText: "", files: [] });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const { isLogin, loginState } = useCustomLoginPage();
  const [rating, handleRating] = useStarRating();
  const [imagePreviewUrl, setImagePreviewUrl] = useState("");
  const uploadRef = useRef();

  const handleChangeReview = (e) => {
    setReview({
      ...review,
      [e.target.name]: e.target.value,
    });
  };

  const handleClickAdd = (e) => {
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
    formData.append("pno", pno);
    formData.append("reviewer", loginState.email);

    setLoading(true);

    postReview(formData, pno).then((data) => {
      setLoading(false);
      setResult(data.prno);
      setReview({ reviewText: "", files: [] });
      handleRating(0);
      reloadReviewList();
    });
  };

  const closeAlertModal = () => {
    setResult(null);
    closeAddModal();
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

  return (
    <div
      className={`modal addModal ${openAddModal ? "show" : ""}`}
      tabIndex="-1"
    >
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={"리뷰가 등록되었습니다."}
          content={`${result}번 리뷰 등록 완료`}
          callbackFn={closeAlertModal}
        />
      ) : (
        <></>
      )}
      <div className="addReview-group">
        <div className="addReview-area">
          <div className="addReview-header">
            <div className="addReview-content title">리뷰 등록</div>
            <button type="button" className="btn-close" onClick={closeAddModal}>
              <IoCloseOutline />
            </button>
          </div>
          <div className="addReview-body">
            <div className="addReview-wrap">
              <div className="addReview-info">작성자</div>
              <div className="addReview-content reviewer">
                {loginState.email}
              </div>
            </div>
            <div className="addReview-wrap">
              <div className="addReview-info">별점</div>
              <StarRating rating={rating} onRatingChange={handleRating} />
            </div>
            <div className="addReview-wrap">
              <div className="addReview-info">리뷰 내용</div>
              <textarea
                className="addReview-content reviewText"
                name="reviewText"
                type={"text"}
                value={review.reviewText}
                onChange={handleChangeReview}
              />
            </div>
            {/* 이미지 미리보기 표시 */}
            <div className="addReview-wrap">
              <div className="addReview-info">리뷰 이미지</div>
              <div className="addReview-box">
                <div className="imgContainer">
                  {imagePreviewUrl ? (
                    <img
                      src={imagePreviewUrl}
                      alt="리뷰 이미지"
                      className="addReviewImage"
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
          <div className="addReview-footer">
            <button
              type="button"
              className="addReview-addBtn"
              onClick={handleClickAdd}
            >
              등록
            </button>
            <button
              type="button"
              className="addReview-closeBtn"
              onClick={closeAddModal}
            >
              닫기
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AddReviewModal;
