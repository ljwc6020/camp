import { useSearchParams } from "react-router-dom";
import "../../styles/pages/listPage.scss";
import ListComponent_p from "../../components/product/ListComponent_p";

const ListPage_p = () => {
  const [queryParams] = useSearchParams();

  const page = queryParams.get("page") ? parseInt(queryParams.get("page")) : 1;
  const size = queryParams.get("size") ? parseInt(queryParams.get("size")) : 10;

  return (
    <>
      <div className="shopList_section">
        <ListComponent_p />
      </div>
    </>
  );
};

export default ListPage_p;
