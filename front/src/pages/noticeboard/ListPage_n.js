import { useNavigate, useSearchParams } from "react-router-dom";
import ListComponent_n from "../../components/noticeboard/ListComponent_n";
import { useCallback } from "react";
import "../../styles/noticeboard/listPage.scss";

const ListPage_n = () => {
  const [queryParams] = useSearchParams();
  const navigate = useNavigate();

  const handleClickList = useCallback(() => {
    navigate({ pathname: "/noticeboard/list" });
  });

  const page = queryParams.get("page") ? parseInt(queryParams.get("page")) : 1;
  const size = queryParams.get("size") ? parseInt(queryParams.get("size")) : 10;

  return (
    <div className="listPageWrap">
      <div className="listPageBg" onClick={handleClickList}>
        <span>- 공지사항 -</span>
      </div>

      <div className="listComponentWrap">
        <ListComponent_n />
      </div>
    </div>
  );
};

export default ListPage_n;
