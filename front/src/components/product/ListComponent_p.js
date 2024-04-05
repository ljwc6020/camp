import { useCallback, useEffect, useState } from "react";
import { getList } from "../../api/productApi";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import "../../styles/components/listComponent.scss";
import PagingComponent from "../common/PagingComponent";
import { API_SERVER_HOST } from "../../api/userApi";
import LoadingModal from "../modal/LoadingModal";
import { useNavigate } from "react-router-dom";
import { formatNumber } from "../../util/formatNumberUtil";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";

const host = API_SERVER_HOST;

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

const ListComponent_p = () => {
  const { page, size, refresh, moveProoductListPage, moveReadPage } =
    useCustomMovePage();
  const [serverData, setServerData] = useState(initState);
  const [loading, setLoading] = useState(false);
  const { isAdmin, loginState } = useCustomLoginPage();
  console.log(loginState);

  useEffect(() => {
    setLoading(true);

    getList({ page, size }).then((data) => {
      setServerData(data);
      setLoading(false);
    });
  }, [page, size, refresh]);

  const navigate = useNavigate();

  const handleClickAdd = useCallback(() => {
    navigate({ pathname: "/product/add" });
    window.scrollTo(0, 0);
  });

  return (
    <div className="shopList_group">
      {loading ? <LoadingModal /> : <></>}
      <div className="shopList_area">
        {serverData.dtoList.map((product) => (
          <div
            key={product.pno}
            className="shopList_wrap"
            onClick={() => moveReadPage(product.pno)}
          >
            <div className="shopList_box">
              <div className="shopList_info">
                <div className="shopList_thum">
                  <img
                    alt={product.pname}
                    src={`${host}/api/products/view/s_${product.uploadFileNames[0]}`}
                  />
                </div>

                <div className="shopList_sum">
                  <div className="shopList_pname">{product.pname}</div>
                  <div className="shopList_price">
                    {formatNumber(product.price)}원
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      {isAdmin && (
        <div className="shopList_btn">
          <div className="shopList_addBtn" onClick={handleClickAdd}>
            상품 등록
          </div>
        </div>
      )}
      <PagingComponent
        serverData={serverData}
        movePage={moveProoductListPage}
      ></PagingComponent>
    </div>
  );
};

export default ListComponent_p;
