import JoinComponent from "../../components/user/JoinComponent";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/user/joinPage.scss";

const JoinPage_u = () => {
  return (
    <BasicLayout>
      <div className="joinWrap">
        <JoinComponent />
      </div>
    </BasicLayout>
  );
};

export default JoinPage_u;
