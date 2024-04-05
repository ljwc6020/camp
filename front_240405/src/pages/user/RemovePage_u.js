import RemoveComponent from "../../components/user/RemoveComponent";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/user/removeWrap.scss";

const RemovePage_u = () => {
  return (
    <BasicLayout>
      <div className="removeWrap">
        <span>
          <a>회원</a>탈퇴
        </span>

        <RemoveComponent />
      </div>
    </BasicLayout>
  );
};

export default RemovePage_u;
