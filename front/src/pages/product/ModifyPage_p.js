import React from "react";
import { useParams } from "react-router-dom";
import ModifyComponent_p from "../../components/product/ModifyComponent_p";
import "../../styles/pages/modifyPage.scss";

const ModifyPage_p = ({}) => {
  const { pno } = useParams();

  return (
    <div className="shopRead_modifyPage">
      <ModifyComponent_p pno={pno} />
    </div>
  );
};

export default ModifyPage_p;
