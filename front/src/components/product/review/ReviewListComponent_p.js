import { useEffect, useState } from "react";
import useCustomMovePage from "../../../hooks/useCustomMovePage";
import { getReviewList } from "../../../api/productReviewApi";
import ReviewReadComponent_p from "./ReviewReadComponent_p";
import AddReviewModal from "./modal/AddReviewModal";
import LoadingModal from "../../modal/LoadingModal";
import StarDisplay from "../../common/star/StarDisplay";
import ReviewQnaPagingComponent from "../../common/ReviewQnaPagingComponent";
import "../../../styles/components/reviewComponent.scss";

const initState = {
  dtoList: [],
  pageNumList: [],
  pageRequestDTO: null,
  prev: false,
  next: false,
  totalCount: 0,
  prevPage: 0,
  nextPage: 0,
  totalPage: 0,
  current: 0,
};

const ReviewListComponent_p = ({ pno }) => {
  const { reviewQnaPage, reviewQnaSize, refresh, moveReviewQnaListPage } =
    useCustomMovePage(pno);
  const [serverData, setServerData] = useState(initState);
  const [viewReview, setViewReview] = useState(null);
  const [openAddReviewModal, setOpenAddReviewModal] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    getReviewList({ page: reviewQnaPage, size: reviewQnaSize }, pno).then(
      (data) => {
        const sortedData = data.dtoList.sort((a, b) => b.prno - a.prno);
        const descData = {
          ...data,
          dtoList: sortedData,
        };
        setServerData(descData);
        setLoading(false);
      }
    );
  }, [pno, reviewQnaPage, reviewQnaSize, refresh]);

  const toggleReview = (prno) => {
    setViewReview((viewReview) => (viewReview === prno ? null : prno));
  };

  const handleAddReviewModal = () => {
    setOpenAddReviewModal((prev) => !prev);
  };

  const reloadReviewList = () => {
    getReviewList({ page: reviewQnaPage, size: reviewQnaSize }, pno).then(
      (data) => {
        const sortedData = data.dtoList.sort((a, b) => b.prno - a.prno);
        const descData = {
          ...data,
          dtoList: sortedData,
        };
        setServerData(descData);
        setLoading(false);
      }
    );
  };

  return (
    <div className="reviewList-group">
      {loading ? <LoadingModal /> : <></>}
      <div className="reviewList-area">
        {serverData.dtoList.map((review) => (
          <div key={review.prno} className="reviewList-wrap">
            <div
              className="reviewList-box"
              onClick={() => toggleReview(review.prno)}
            >
              <div className="reviewList-content">
                <div className="reviewList-score list">
                  <StarDisplay score={review.score} />
                </div>
                <div className="reviewList-reviewText list">
                  {review.reviewText}
                </div>
                <div className="reviewList-registeredAt list">
                  {review.registeredAt}
                </div>
                <div className="reviewList-reviewer list">
                  {review.reviewer}
                </div>
              </div>
            </div>
            <div className="reviewReadContainer">
              {viewReview === review.prno && (
                <ReviewReadComponent_p
                  prno={review.prno}
                  reloadReviewList={reloadReviewList}
                />
              )}
            </div>
          </div>
        ))}
      </div>
      <ReviewQnaPagingComponent
        serverData={serverData}
        movePage={moveReviewQnaListPage}
      ></ReviewQnaPagingComponent>
      <div className="reviewList-btn">
        <button
          type="button"
          className="reviewList-addBtn"
          onClick={handleAddReviewModal}
        >
          등록
        </button>
        {openAddReviewModal && (
          <AddReviewModal
            openAddModal={openAddReviewModal}
            closeAddModal={() => setOpenAddReviewModal(false)}
            pno={pno}
            reloadReviewList={reloadReviewList}
          />
        )}
      </div>
    </div>
  );
};

export default ReviewListComponent_p;
