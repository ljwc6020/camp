import React, { useCallback, useState } from "react";
import {
  createSearchParams,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import ReadComponent_p from "../../components/product/ReadComponent_p";
import ReviewListComponent_p from "../../components/product/review/ReviewListComponent_p";
import QnaListComponent_p from "../../components/product/qna/QnaListComponent_p";
import "../../styles/pages/readPage.scss";

const ReadPage_p = () => {
  const { pno } = useParams();
  const navigate = useNavigate();
  const [queryParams] = useSearchParams();

  const page = queryParams.get("page") ? parseInt(queryParams.get("page")) : 1;
  const size = queryParams.get("size") ? parseInt(queryParams.get("size")) : 10;
  const queryString = createSearchParams({ page, size }).toString();
  const [selectedTab, setSelectedTab] = useState("reviews");

  const moveModifyPage = useCallback(
    (pno) => {
      navigate({ pathname: `/product/modify/${pno}`, search: queryString });
    },
    [pno, page, size]
  );

  const moveListPage = useCallback(() => {
    navigate({ pathname: `/product/list`, search: queryString });
  }, [page, size]);

  const [selectReviewQna, setSelectReviewQna] = useState(true);

  return (
    <div className="readPage_wrap">
      <div className="readPage_section">
        <ReadComponent_p pno={pno} />
      </div>
      <div className="reviewQna_section">
        <div className="reviewQna_Btn">
          <button
            className={selectedTab === "reviews" ? "active" : ""}
            onClick={() => {
              setSelectedTab("reviews");
              setSelectReviewQna(true);
            }}
          >
            리뷰
          </button>
          <button
            className={selectedTab === "qna" ? "active" : ""}
            onClick={() => {
              setSelectedTab("qna");
              setSelectReviewQna(false);
            }}
          >
            Q&A
          </button>
        </div>
        <div className="reviewQna_Container">
          {selectReviewQna ? (
            <ReviewListComponent_p pno={pno} />
          ) : (
            <QnaListComponent_p pno={pno} />
          )}
        </div>
      </div>
    </div>
  );
};

export default ReadPage_p;
