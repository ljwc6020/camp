import { useEffect } from "react";
import { useState } from "react";
import { getOne } from "../../api/noticeBoardApi";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";

const initState = {
  nbno: 0,
  title: "",
  writer: "",
  content: "",
  totalReplies: 0,
  registeredAt: "",
  modifiedAt: "",
};

const ReadComponent_n = ({ nbno }) => {
  const [noticeboard, setNoticeboard] = useState(initState);
  const { moveListPage, moveModifyPage } = useCustomMovePage();
  const { loginState } = useCustomLoginPage();
  const isUser = noticeboard.writer === loginState.email;

  useEffect(() => {
    getOne(nbno).then((data) => {
      console.log(data);
      setNoticeboard(data);
      window.scrollTo(0, 0);
    });
  }, [nbno]);

  const getLatestTime = () => {
    const registeredDate = new Date(noticeboard.registeredAt);
    const modifiedDate = new Date(noticeboard.modifiedAt);

    if (!noticeboard.modifiedAt || registeredDate >= modifiedDate) {
      return noticeboard.registeredAt;
    } else {
      return noticeboard.modifiedAt;
    }
  };

  return (
    <div className="readPageInfoBundle">
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">
            글 번호
          </div>
          <div className="readDiv">{noticeboard.nbno}</div>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">제목</div>
          <div className="readDiv1">{noticeboard.title}</div>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">
            작성자
          </div>
          <div className="readDiv2"> {noticeboard.writer}</div>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">내용</div>
          <div className="readDiv3">{noticeboard.content}</div>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold text-white">
            최근 변경 시간
          </div>
          <div className="readDiv5">{getLatestTime()}</div>
        </div>
      </div>
      <div className="readBtnBundle">
        <button
          type="button"
          className="rounded p-4 m-2 text-xl w-32 text-white bg-yellow-500"
          onClick={() => moveListPage()}
        >
          목록으로
        </button>
        {isUser && (
          <button
            type="button"
            className="rounded p-4 m-2 text-xl w-32 text-white bg-yellow-500"
            onClick={() => moveModifyPage(nbno)}
          >
            수정
          </button>
        )}
      </div>
    </div>
  );
};

export default ReadComponent_n;
