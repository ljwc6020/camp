import ModifyComponent from "../../components/user/ModifyComponent";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/user/modifyPage.scss";

const ModfyPage_u = () => {
  return (
    <BasicLayout>
      <div className="modifyWrap">
        <div className="modifyTitle">정보 수정</div>

        <div className="modifyComponent">
          <ModifyComponent></ModifyComponent>
        </div>
      </div>
    </BasicLayout>
  );
};

export default ModfyPage_u;
