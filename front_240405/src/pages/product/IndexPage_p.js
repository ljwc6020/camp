import { Outlet, useLocation } from "react-router-dom";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/pages/indexPage.scss";

const IndexPage_p = () => {
  const location = useLocation();

  // `/cart` 경로일 때 타이틀을 숨김
  const hideTitle = location.pathname === "/product/cart";

  return (
    <BasicLayout>
      <div className="wrap">
        {!hideTitle && (
          <div className="shopList_title">
            <ul>
              <li>- 쇼핑몰 -</li>
              <li></li>
            </ul>
          </div>
        )}
        <div className="indexPage">
          <Outlet />
        </div>
      </div>
    </BasicLayout>
  );
};

export default IndexPage_p;
