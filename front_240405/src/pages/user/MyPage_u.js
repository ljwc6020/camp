import MyPageComponent from "../../components/user/MyPageComponent";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/user/myPage.scss";

const MyPage_u = () => {
  return (
    <BasicLayout>
      <div className="myPageBg">
        <div className="myPageSection">
          <span>- 마이페이지 -</span>
        </div>
        <div className="myPageComponentSection">
          <MyPageComponent></MyPageComponent>
        </div>
      </div>
    </BasicLayout>
  );
};

export default MyPage_u;
