import { useState } from "react";
import { postOne } from "../../api/noticeBoardApi";
import AlertModal from "../modal/AlertModal";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import LoadingModal from "../modal/LoadingModal";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";

const initState = {
  title: "",
  content: "",
};

const AddComponent_n = () => {
  const [noticeboard, setNoticeboard] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const { moveListPage } = useCustomMovePage();
  const [loading, setLoading] = useState(false);
  const { isLogin, loginState } = useCustomLoginPage();

  const handleChangeNoticeboard = (e) => {
    noticeboard[e.target.name] = e.target.value;
    setNoticeboard({ ...noticeboard, writer: loginState.email });
  };

  const handleClickAdd = () => {
    setLoading(true);
    postOne(noticeboard).then((data) => {
      setLoading(false);
      setResult(data.register);
      setNoticeboard({ ...initState });
    });
  };

  const closeAlertModal = () => {
    setResult(null);
    moveListPage();
  };

  return (
    <div className="addPageSection">
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={"공지사항이 등록되었습니다."}
          content={`${result}번 공지사항 등록 완료`}
          callbackFn={closeAlertModal}
        />
      ) : (
        <></>
      )}
      <div className="inputBundle">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">제목</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-500 shadow-md"
            name="title"
            type={"text"}
            value={noticeboard.title}
            onChange={handleChangeNoticeboard}
          ></input>
        </div>

        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">
            작성자
          </div>
          <div className="w-4/5 p-6 rounded-r border border-solid shadow-md bg-gray-300">
            {loginState.email}
          </div>
        </div>

        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">내용</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-500 shadow-md"
            name="content"
            type={"text"}
            value={noticeboard.content}
            onChange={handleChangeNoticeboard}
          ></input>
        </div>
      </div>

      <div className="addPageBtnWrap">
        <div className="relative mb-4 flex p-4 flex-wrap items-stretch">
          <button
            type="button"
            className="rounded p-4 w-36 bg-yellow-500 text-xl  text-white "
            onClick={handleClickAdd}
          >
            등록
          </button>
        </div>
      </div>
    </div>
  );
};

export default AddComponent_n;
