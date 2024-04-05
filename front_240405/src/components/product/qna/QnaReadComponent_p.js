import { useEffect, useState } from "react";
import { getQna } from "../../../api/productQnaApi";
import ModifyQnaModal from "./modal/ModifyQnaModal";
import LoadingModal from "../../modal/LoadingModal";
import useCustomLoginPage from "../../../hooks/useCustomLoginPage";
import "../../../styles/components/qnaComponent.scss";

const initState = {
  qno: 0,
  pno: 0,
  product: "",
  question: "",
  answer: "",
  authorName: "",
  answered: false,
  askedAt: "",
  answeredAt: "",
};

const QnaReadComponent_p = ({ qno, reloadQnaList, answered }) => {
  const [qna, setQna] = useState(initState);
  const [openModifyQnaModal, setOpenModifyQnaModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const { isAdmin, loginState } = useCustomLoginPage();
  const isUser = qna.authorName === loginState.email;

  useEffect(() => {
    setLoading(true);
    getQna(qno).then((data) => {
      console.log(data);
      setQna(data);
      setLoading(false);
    });
  }, [qno]);

  const handleModifyQnaModal = () => {
    setOpenModifyQnaModal((prev) => !prev);
  };

  const reloadQnaRead = () => {
    getQna(qno).then((data) => {
      console.log(data);
      setQna(data);
    });
  };

  return (
    <div className="qnaRead-group">
      {loading ? <LoadingModal /> : <></>}
      <div className="qnaRead-area">
        <div className="qnaRead-wrap">
          <div className="qnaRead-content">
            <div className="qnaRead-box">
              <div className="qnaRead-answer">└ 답변: {qna.answer}</div>
              <div className="qnaRead-answerer">판매자</div>
              <div className="qnaRead-answeredAt">{qna.answeredAt}</div>
            </div>
          </div>
        </div>
      </div>
      <div className="qnaRead-btn">
        {(isUser || isAdmin) && (
          <button
            type="button"
            className="qnaRead-modifyBtn"
            onClick={handleModifyQnaModal}
          >
            수정
          </button>
        )}
        {openModifyQnaModal && (
          <ModifyQnaModal
            openModifyModal={openModifyQnaModal}
            closeModifyModal={() => setOpenModifyQnaModal(false)}
            reloadQnaList={reloadQnaList}
            reloadQnaRead={reloadQnaRead}
            qno={qno}
          />
        )}
      </div>
    </div>
  );
};

export default QnaReadComponent_p;
