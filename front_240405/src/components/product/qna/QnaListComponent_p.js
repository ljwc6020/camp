import { useEffect, useState } from "react";
import useCustomMovePage from "../../../hooks/useCustomMovePage";
import { getQnaList } from "../../../api/productQnaApi";
import ReviewQnaPagingComponent from "../../common/ReviewQnaPagingComponent";
import QnaReadComponent_p from "./QnaReadComponent_p";
import AddQnaModal from "./modal/AddQnaModal";
import LoadingModal from "../../modal/LoadingModal";
import useCustomLoginPage from "../../../hooks/useCustomLoginPage";
import "../../../styles/components/qnaComponent.scss";

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

const QnaListComponent_p = ({ pno }) => {
  const { reviewQnaPage, reviewQnaSize, refresh, moveReviewQnaListPage } =
    useCustomMovePage(pno);
  const [serverData, setServerData] = useState(initState);
  const [viewQna, setViewQna] = useState(null);
  const [openAddQnaModal, setOpenAddQnaModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const { isAdmin, loginState } = useCustomLoginPage();

  useEffect(() => {
    setLoading(true);
    getQnaList({ page: reviewQnaPage, size: reviewQnaSize }, pno).then(
      (data) => {
        const sortedData = data.dtoList.sort((a, b) => b.qno - a.qno);
        const descData = {
          ...data,
          dtoList: sortedData,
        };
        setServerData(descData);
        setLoading(false);
      }
    );
  }, [pno, reviewQnaPage, reviewQnaSize, refresh]);

  const toggleQna = (qno) => {
    setViewQna((prevQno) => (prevQno === qno ? null : qno));
  };

  const handleAddQnaModal = () => {
    setOpenAddQnaModal((prev) => !prev);
  };

  // QnA 리스트를 내림차순으로 정렬하여 재로딩
  const reloadQnaList = () => {
    getQnaList({ page: reviewQnaPage, size: reviewQnaSize }, pno).then(
      (data) => {
        const sortedData = data.dtoList.sort((a, b) => b.qno - a.qno);
        const descData = {
          ...data,
          dtoList: sortedData,
        };
        setServerData(descData);
        setLoading(false); // setLoading 호출 추가
      }
    );
  };

  return (
    <div className="qnaList-group">
      {loading ? <LoadingModal /> : <></>}
      <div className="qnaList-area">
        <ul className="qnaList-index">
          <li className="qnaList-qno">번호</li>
          <li className="qnaList-answered">답변상태</li>
          <li className="qnaList-question">문의 내용</li>
          <li className="qnaList-authorName">작성자</li>
          <li className="qnaList-askedAt">작성일</li>
        </ul>
        {serverData.dtoList.map((qna) => (
          <div key={qna.qno} className="qnaList-wrap">
            <div className="qnaList-box" onClick={() => toggleQna(qna.qno)}>
              <div className="qnaList-content">
                <div className="qnaList-qno list">{qna.qno}</div>
                <div className="qnaList-answered list">
                  {qna.answered ? "답변 완료" : "답변 대기중"}
                </div>
                <div className="qnaList-question list">{qna.question}</div>
                <div className="qnaList-authorName list">{qna.authorName}</div>
                <div className="qnaList-askedAt list">{qna.askedAt}</div>
              </div>
            </div>
            <div className="qnaReadContainer">
              {viewQna === qna.qno &&
                (isAdmin ||
                  qna.authorName === loginState.email ||
                  qna.answer) && (
                  <QnaReadComponent_p
                    qno={qna.qno}
                    reloadQnaList={reloadQnaList}
                    answered={qna.answered}
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
      <div className="qnaList-btn">
        <button
          type="button"
          className="qnaList-addBtn"
          onClick={handleAddQnaModal}
        >
          등록
        </button>
        {openAddQnaModal && (
          <AddQnaModal
            pno={pno}
            openAddModal={openAddQnaModal}
            closeAddModal={() => setOpenAddQnaModal(false)}
            reloadQnaList={reloadQnaList}
          />
        )}
      </div>
    </div>
  );
};

export default QnaListComponent_p;
