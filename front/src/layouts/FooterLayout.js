import React from "react";
import "../styles/layouts/layout.scss";
import logo2 from "../img/logo.png";
import { Link } from "react-router-dom";

const FooterLayout = () => {
  return (
    <footer>
      <div className="footer_bg">
        <div className="logo2">
          <img src={logo2} alt="logo" />
        </div>
        <div className="footerwrap">
          <ul>
            <li>
              <Link to="/">뷰캠프</Link>
            </li>
            <li>&ensp;|&ensp;</li>
            <li>
              <Link to="/">위치정보 이용약관</Link>
            </li>
            <li>&ensp;|&ensp;</li>
            <li>
              <Link to="/">개인정보처리방침</Link>
            </li>
            <li>&ensp;|&ensp;</li>
            <li>
              <Link to="/">운영정책</Link>
            </li>
            <li>&ensp;|&ensp;</li>
            <li>
              <Link to="/">Contact Us</Link>
            </li>
          </ul>
          <div>
            ※ 저희는 예약 시스템만 지원합니다 (예약관련업무는 캠핑장 책임하에
            운영됩니다)
          </div>
          <div>COPYRIGHT© CAMPING SERVICE INC. ALL RIGHT RESERVED</div>
        </div>
      </div>
    </footer>
  );
};

export default FooterLayout;
