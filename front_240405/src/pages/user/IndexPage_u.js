import React, { useCallback } from "react";
import { Outlet, useNavigate } from "react-router-dom";
import BasicLayout from "../../layouts/BasicLayout";
import "../../styles/pages/indexPage.scss";

const IndexPage_n = () => {
  const navigate = useNavigate();

  const handleClickList = useCallback(() => {
    navigate({ pathname: "join" });
  });

  const handleClickAdd = useCallback(() => {
    navigate({ pathname: "login" });
  });

  return (
    <div className="indexPage">
      <Outlet />
    </div>
  );
};

export default IndexPage_n;
