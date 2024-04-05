import React, { useEffect, useState } from "react";
import { putQna, deleteQna, getQna } from "../../../../api/productQnaApi";
import LoadingModal from "../../../modal/LoadingModal";
import AlertModal from "../../../modal/AlertModal";
import { IoCloseOutline } from "react-icons/io5";
import useCustomLoginPage from "../../../../hooks/useCustomLoginPage";
import "../../../../styles/components/modal/modifyModal.scss";

const initState = {
  question: "",
  answer: "",
  answered: false,
};

const ModifyQnaModal = ({
  qno,
  openModifyModal,
  closeModifyModal,
  reloadQnaList,
  reloadQnaRead,
}) => {
  const [qna, setQna] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const { isLogin, isAdmin, loginState } = useCustomLoginPage();
  const isUser = qna.authorName === loginState.email;

  useEffect(() => {
    setLoading(true);
    getQna(qno).then((data) => {
      setQna(data);
      setLoading(false);
    });
  }, [qno]);

  const handleChangeQna = (e) => {
    const { name, value } = e.target;
    const updatedValue = name === "answered" ? value === "true" : value;
    setQna({ ...qna, [name]: updatedValue });
  };

  const handleClickModify = () => {
    const modifiedQna = {
      authorName: qna.authorName,
      qno: qna.qno,
      question: qna.question,
      answer: qna.answer,
      answered: qna.answered,
    };

    setLoading(true);

    putQna(qna.qno, modifiedQna).then((data) => {
      console.log("modify result: " + data);
      setResult("수정 완료");
      setLoading(false);
      reloadQnaList();
      reloadQnaRead();
    });
  };

  const handleClickDelete = () => {
    setLoading(true);
    const deleteQnaDTO = {
      authorName: qna.authorName,
      qno: qna.qno,
    };
    deleteQna(deleteQnaDTO).then((data) => {
      setResult("삭제 완료");
      setLoading(false);
    });
  };

  const closeAlertModal = () => {
    if (result === "수정 완료") {
      closeModifyModal();
    } else if (result === "삭제 완료") {
      reloadQnaList();
    }

    setResult(null);
  };

  return (
    <div
      className={`modal modifyModal ${openModifyModal ? "show" : ""} ${
        isAdmin ? "" : "userView"
      }`}
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
      <div className="modifyQna-group">
        <div className="modifyQna-area">
          <div className="modifyQna-header">
            <div className="modifyQna-title">문의 수정</div>
            <button
              type="button"
              className="btn-close"
              onClick={closeModifyModal}
            >
              <IoCloseOutline />
            </button>
          </div>
          <div className="modifyQna-body">
            <div className="modifyQna-wrap">
              <div className="modifyQna-info">문의 작성자</div>
              <div className="modifyQna-content authorName">
                {loginState.email}
              </div>
            </div>
            {isUser && (
              <div className="modifyQna-wrap">
                <div className="modifyQna-info">문의 내용</div>
                <textarea
                  className="modifyQna-content question"
                  name="question"
                  type={"text"}
                  value={qna.question}
                  onChange={handleChangeQna}
                />
              </div>
            )}
            {isAdmin && !isUser && (
              <div className="modifyQna-wrap">
                <div className="modifyQna-info">문의 내용</div>
                <div className="modifyQna-content question readonly">
                  {qna.question}
                </div>
              </div>
            )}
          </div>
          {isAdmin && (
            <div className="modifyQna-body">
              <div className="modifyQna-wrap">
                <div className="modifyQna-info">답변 작성자</div>
                <div className="modifyQna-content authorName">판매자</div>
              </div>
              <div className="modifyQna-wrap">
                <div className="modifyQna-info">답변상태</div>
                <div className="modifyQna-content answered">
                  <select
                    name="answered"
                    value={qna.answered}
                    onChange={handleChangeQna}
                  >
                    <option value={false}>답변 대기중</option>
                    <option value={true}>답변완료</option>
                  </select>
                </div>
              </div>
              <div className="modifyQna-wrap">
                <div className="modifyQna-info">답변</div>
                <textarea
                  className="modifyQna-content answer"
                  name="answer"
                  type={"text"}
                  value={qna.answer}
                  onChange={handleChangeQna}
                />
              </div>
            </div>
          )}
          <div className="modifyQna-footer">
            <button
              type="button"
              className="modifyQna-modifyBtn"
              onClick={handleClickModify}
            >
              수정
            </button>
            {isUser && (
              <button
                type="button"
                className="modifyQna-deleteBtn"
                onClick={handleClickDelete}
              >
                삭제
              </button>
            )}
            <button
              type="button"
              className="modifyQna-closeBtn"
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

export default ModifyQnaModal;
