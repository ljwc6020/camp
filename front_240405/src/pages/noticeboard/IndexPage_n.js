import { Outlet } from "react-router-dom";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/pages/indexPage.scss";

const IndexPage_n = () => {
  return (
    <BasicLayout>
      <div className="indexPage_wrap">
        <div className="indexPage_container">
          <div className="indexPage">
            <Outlet />
          </div>
        </div>
      </div>
    </BasicLayout>
  );
};

export default IndexPage_n;
