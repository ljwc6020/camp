import { useEffect, useState } from "react";
import { deleteOne, getOne, putOne } from "../../api/noticeBoardApi";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import AlertModal from "../modal/AlertModal";
import LoadingModal from "../modal/LoadingModal";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";

const initState = {
  title: "",
  content: "",
};

const ModifyComponent_n = ({ nbno }) => {
  const [noticeboard, setNoticeboard] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const { moveListPage, moveReadPage } = useCustomMovePage();
  const [loading, setLoading] = useState(false);
  const { loginState } = useCustomLoginPage();

  useEffect(() => {
    setLoading(true);
    getOne(nbno).then((data) => {
      setNoticeboard(data);
      setLoading(false);
    });
  }, [nbno]);

  const handleChangeNoticeboard = (e) => {
    noticeboard[e.target.name] = e.target.value;

    setNoticeboard({ ...noticeboard });
  };

  const handleClickModify = () => {
    const modifiedNoticeboard = {
      nbno: noticeboard.nbno,
      title: noticeboard.title,
      content: noticeboard.content,
      writer: noticeboard.writer,
    };
    setLoading(true);

    putOne(modifiedNoticeboard).then((data) => {
      console.log("modify result: " + data);
      setResult("수정 완료");
      setLoading(false);
    });
  };

  const handleClickDelete = () => {
    const deleteNoticeboard = {
      nbno: noticeboard.nbno,
      title: noticeboard.title,
      content: noticeboard.content,
      writer: noticeboard.writer,
    };
    setLoading(true);
    deleteOne(deleteNoticeboard).then((data) => {
      console.log("delete result: " + data);
      setResult("삭제 완료");
      setLoading(false);
    });
  };

  const closeAlertModal = () => {
    if (result === "삭제 완료") {
      moveListPage();
    } else {
      moveReadPage(nbno);
    }

    setResult(null);
  };

  return (
    <div className="modifyInfoBundle">
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={"처리 결과"}
          content={result}
          callbackFn={closeAlertModal}
        ></AlertModal>
      ) : (
        <></>
      )}
      <div className="flex justify-center mt-10">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">게시글 번호</div>
          <div className="w-4/5 p-6 rounded-r border border-solid border-yellow-500 shadow-md bg-gray-100">
            {noticeboard.nbno}
          </div>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">작성자</div>
          <div className="w-4/5 p-6 rounded-r border border-solid  border-yellow-500 shadow-md bg-gray-100">
            {loginState.email}
          </div>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">제목</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-yellow-500 shadow-md"
            name="title"
            type={"text"}
            value={noticeboard.title}
            onChange={handleChangeNoticeboard}
          ></input>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">내용</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-yellow-500 shadow-md"
            name="content"
            type={"text"}
            value={noticeboard.content}
            onChange={handleChangeNoticeboard}
          ></input>
        </div>
      </div>

      <div className="flex justify-end p-4">
        <button
          type="button"
          className="rounded p-4 m-2 text-xl w-32 text-white bg-yellow-500"
          onClick={handleClickModify}
        >
          수정
        </button>
        <button
          type="button"
          className="inline-block rounded p-4 m-2 text-xl w-32  text-white bg-yellow-500"
          onClick={handleClickDelete}
        >
          삭제
        </button>
      </div>
    </div>
  );
};

export default ModifyComponent_n;
