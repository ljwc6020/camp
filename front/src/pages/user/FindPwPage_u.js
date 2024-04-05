import FindPwComponent from "../../components/user/FindPwComponent";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/user/findPage.scss";

const FindPw_u = () => {
  return (
    <BasicLayout>
      <div className="wrap">
        <FindPwComponent />
      </div>
    </BasicLayout>
  );
};

export default FindPw_u;
