import React from "react";
import { useParams } from "react-router-dom";
import ModifyComponent_n from "../../components/noticeboard/ModifyComponent_n";
import "../../styles/noticeboard/modifyPage.scss";

const ModifyPage_n = () => {
  const { nbno } = useParams();

  return (
    <div className="modifyWrap">
      <div className="modifyBg">- 게시글 수정 -</div>
      <ModifyComponent_n nbno={nbno} />
    </div>
  );
};

export default ModifyPage_n;
