import React from "react";
import HeaderLayout from "./HeaderLayout";
import FooterLayout from "./FooterLayout";
import "../styles/pages/mainPage.scss";
import FixedMenu from "../components/common/FixedMenu";

const BasicLayout = ({ children }) => {
  return (
    <>
      <HeaderLayout />
      <FixedMenu />
      {children}
      <FooterLayout />
    </>
  );
};

export default BasicLayout;
