import { useEffect, useState } from "react";
import { getReview } from "../../../api/productReviewApi";
import { API_SERVER_HOST } from "../../../api/userApi";
import ModifyReviewModal from "./modal/ModifyReviewModal";
import ImageModal from "../../modal/ImageModal";
import useCustomLoginPage from "../../../hooks/useCustomLoginPage";
import "../../../styles/components/reviewComponent.scss";

const initState = {
  prno: 0,
  pno: 0,
  reviewText: "",
  reviewer: "",
  score: 0,
  registeredAt: "",
  modifiedAt: "",
  uploadFileNames: [],
};

const host = API_SERVER_HOST;

const ReviewReadComponent_p = ({ prno, reloadReviewList }) => {
  const [review, setReview] = useState(initState);
  const [openModifyReviewModal, setOpenModifyReviewModal] = useState(false);
  const [openImg, setOpenImg] = useState(false);
  const [selectedImgPath, setSelectedImgPath] = useState("");
  const { loginState } = useCustomLoginPage();
  const isUser = review.reviewer === loginState.email;

  useEffect(() => {
    getReview(prno).then((data) => {
      console.log(data);
      setReview(data);
    });
  }, [prno]);

  const handleModifyReviewModal = () => {
    setOpenModifyReviewModal((prev) => !prev);
  };

  const reloadReviewRead = () => {
    getReview(prno).then((data) => {
      console.log(data);
      setReview(data);
    });
  };

  const handleOpenImg = (imgFile) => {
    setSelectedImgPath(`${host}/review/view/${imgFile}`);
    setOpenImg(true);
  };

  const closeImageModal = () => {
    setOpenImg(false);
  };

  return (
    <div className="reviewRead-group">
      <div className="reviewRead-area">
        <ul className="reviewRead-wrap">
          <li>상품 번호: {review.pno},</li>
          <li>리뷰 번호: {review.prno}</li>
        </ul>
        <div
          className={`reviewRead-image ${
            review.uploadFileNames.length === 0 ? "reviewRead-noImage" : ""
          }`}
        >
          {review.uploadFileNames.map((imgFile, i) => (
            <img
              alt="review image"
              key={i}
              src={`${host}/review/view/${imgFile}`}
              onClick={() => handleOpenImg(imgFile)}
            />
          ))}
        </div>
        {openImg && (
          <ImageModal
            openImg={openImg}
            callbackFn={closeImageModal}
            imagePath={selectedImgPath}
          />
        )}
        <div className="reviewRead-box">{review.reviewText}</div>
      </div>

      <div className="reviewRead-btn">
        {isUser && (
          <button
            type="button"
            className="reviewRead-modifyBtn"
            onClick={handleModifyReviewModal}
          >
            수정
          </button>
        )}
        {openModifyReviewModal && (
          <ModifyReviewModal
            openModifyModal={openModifyReviewModal}
            closeModifyModal={() => setOpenModifyReviewModal(false)}
            reloadReviewList={reloadReviewList}
            reloadReviewRead={reloadReviewRead}
            prno={prno}
          />
        )}
      </div>
    </div>
  );
};

export default ReviewReadComponent_p;
