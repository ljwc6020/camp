import React, { useEffect, useState } from "react";
import { postQna } from "../../../../api/productQnaApi";
import "../../../../styles/components/modal/addModal.scss";
import LoadingModal from "../../../modal/LoadingModal";
import AlertModal from "../../../modal/AlertModal";
import { IoCloseOutline } from "react-icons/io5";
import useCustomLoginPage from "../../../../hooks/useCustomLoginPage";
import "../../../../styles/components/modal/addModal.scss";

const initState = {
  question: "",
};

const AddQnaModal = ({ openAddModal, closeAddModal, reloadQnaList, pno }) => {
  const [qna, setQna] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const { isLogin, loginState } = useCustomLoginPage();

  const handleChangeQna = (e) => {
    qna[e.target.name] = e.target.value;
    setQna({
      ...qna,
      pno,
      authorName: loginState.email,
    });
  };

  const handleClickAdd = (e) => {
    setLoading(true);
    postQna(qna).then((data) => {
      setLoading(false);
      setResult(data);
      setQna({ ...initState });
      reloadQnaList();
    });
  };

  const closeAlertModal = () => {
    setResult(null);
    closeAddModal();
  };

  return (
    <div
      className={`modal addModal ${openAddModal ? "show" : ""}`}
      tabIndex="-1"
    >
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={"문의가 등록되었습니다."}
          content={`${result}번 문의 등록 완료`}
          callbackFn={closeAlertModal}
        />
      ) : (
        <></>
      )}
      <div className="addQna-group">
        <div className="addQna-area">
          <div className="addQna-header">
            <div className="addQna-content title">문의 등록</div>
            <button type="button" className="btn-close" onClick={closeAddModal}>
              <IoCloseOutline />
            </button>
          </div>
          <div className="addQna-body">
            <div className="addQna-wrap">
              <div className="addQna-info">문의 작성자</div>
              <div className="addQna-content authorName">
                {loginState.email}
              </div>
            </div>
            <div className="addQna-wrap">
              <div className="addQna-info">문의 내용</div>
              <textarea
                className="addQna-content question"
                name="question"
                type={"text"}
                value={qna.question}
                onChange={handleChangeQna}
              />
            </div>
          </div>
          <div className="addQna-footer">
            <button
              type="button"
              className="addQna-addBtn"
              onClick={handleClickAdd}
            >
              등록
            </button>
            <button
              type="button"
              className="addQna-closeBtn"
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

export default AddQnaModal;
