import { useCallback, useEffect, useState } from "react";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import { getList } from "../../api/noticeBoardApi";
import PagingComponent from "../common/PagingComponent";
import { useNavigate } from "react-router-dom";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";
import "../../styles/components/listComponent.scss";

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

const ListComponent_n = () => {
  const [noticeboard, setNoticeboard] = useState(initState);
  const { page, size, moveListPage, moveReadPage, refresh } =
    useCustomMovePage();
  const [serverData, setServerData] = useState(initState);
  const { isAdmin, loginState } = useCustomLoginPage();
  console.log(loginState);

  useEffect(() => {
    getList({ page, size }).then((data) => {
      console.log(data);
      setServerData(data);
    });
  }, [page, size, refresh]);

  const navigate = useNavigate();

  const handleClickAdd = useCallback(() => {
    navigate({ pathname: "/noticeboard/add" });
  });

  const getLatestTime = (noticeboard) => {
    const registeredDate = new Date(noticeboard.registeredAt);
    const modifiedDate = new Date(noticeboard.modifiedAt);

    if (!noticeboard.modifiedAt || registeredDate >= modifiedDate) {
      return noticeboard.registeredAt;
    } else {
      return noticeboard.modifiedAt;
    }
  };

  return (
    <div className="nboardList_group">
      <div className="nboardList_area">
        <ul className="nboardList_index">
          <li className="nboardList_nbno">번호</li>
          <li className="nboardList_title">내용</li>
          <li className="nboardList_writer">작성자</li>
          <li className="nboardList_time">수정일</li>
        </ul>
        {serverData.dtoList.map((noticeboard) => (
          <div
            key={noticeboard.nbno}
            className="nboardList_wrap"
            onClick={() => moveReadPage(noticeboard.nbno)}
            style={{ backgroundColor: "#FFFAFA" }}
          >
            <div className="nboardList_box">
              <div className="nboardList_nbno">{noticeboard.nbno}</div>
              <div className="nboardList_title">{noticeboard.title}</div>
              <div className="nboardList_writer">{noticeboard.writer}</div>
              <div className="nboardList_time">
                {getLatestTime(noticeboard)}
              </div>
            </div>
          </div>
        ))}
      </div>
      {isAdmin && (
        <button className="listPageBtn" onClick={handleClickAdd}>
          공지사항 작성
        </button>
      )}
      <PagingComponent
        serverData={serverData}
        movePage={moveListPage}
      ></PagingComponent>
    </div>
  );
};

export default ListComponent_n;
