import React, { useCallback } from "react";
import {
  createSearchParams,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import ReadComponent_n from "../../components/noticeboard/ReadComponent_n";
import "../../styles/noticeboard/readPage.scss";

const ReadPage_n = () => {
  const { nbno } = useParams();

  const navigate = useNavigate();

  const [queryParams] = useSearchParams();

  const page = queryParams.get("page") ? parseInt(queryParams.get("page")) : 1;
  const size = queryParams.get("size") ? parseInt(queryParams.get("size")) : 10;

  const queryString = createSearchParams({ page, size }).toString();

  const moveModifyPage = useCallback(
    (nbno) => {
      navigate({
        pathname: `/noticeboard/modify/${nbno}`,
        search: queryString,
      });
    },
    [nbno, page, size]
  );

  const moveListPage = useCallback(() => {
    navigate({ pathname: `/noticeboard/list`, search: queryString });
  }, [page, size]);

  return (
    <div className="readWrap">
      <ReadComponent_n nbno={nbno} />
    </div>
  );
};

export default ReadPage_n;
