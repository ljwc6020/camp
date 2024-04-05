import React, { useState } from "react";
import { Link } from "react-router-dom";
import "../styles/layouts/layout.scss";
import logo from "../img/logo.png";
import bar from "../img/bars.svg";
import user from "../img/user1.svg";
import signup from "../img/signup.svg";
import cart from "../img/cart.svg";
import logout from "../img/logout.svg";
import idcard from "../img/idcard.svg";
import HiddenMenu from "../components/main/HiddenMenu";
import { useSelector } from "react-redux";

function Header() {
  const [isActive, setIsActive] = useState(false); // 상태 변수를 사용하여 메뉴의 활성/비활성 상태를 관리
  const loginState = useSelector((state) => state.loginSlice);
  const email = loginState.email;

  // 햄버거 버튼을 클릭할 때 실행되는 함수
  const toggleMenu = () => {
    setIsActive(!isActive); // 상태를 반전시킴
  };

  return (
    <header>
      <div className="headerwrap">
        <h1>
          <Link to={"/"}>
            <img src={logo} alt="logo" />
          </Link>
        </h1>
        <ul id="gnb">
          <li>
            <Link to={"/camping"}>캠핑장</Link>
          </li>
          <li>
            <Link to={"/product"}>쇼핑몰</Link>
          </li>
          <li>
            <Link to={"/noticeboard"}>공지사항</Link>
          </li>
        </ul>
        <ul className="lnb">
          <li>
            {!loginState.email ? (
              <div>
                <Link to={"/user/login"}>로그인</Link>
              </div>
            ) : (
              <div>
                <Link to={"/user/logout"}>로그아웃</Link>
              </div>
            )}
          </li>
          <li>
            {!loginState.email ? (
              <Link to={"/user/join"}>회원가입</Link>
            ) : (
              <Link to={`/user/mypage/${email}`}>마이페이지</Link>
            )}
          </li>
        </ul>

        {/* 반응형 */}
        <div className="mobile">
          <button className="btn-ham" onClick={toggleMenu}>
            <img src={bar} alt="bar" />
          </button>
          <HiddenMenu isActive={isActive} />{" "}
          {/* HiddenMenu 컴포넌트에 상태 전달 */}
          <Link to={"/"}>
            <img src={logo} className="logo-m" alt="로고" />
          </Link>
          <ul className="lnb-m">
            {!loginState.email ? (
              <li>
                <Link to={"/user/login"}>
                  <img src={user} width="17" height="48" alt="로그인" />
                </Link>
              </li>
            ) : (
              <li>
                <Link to={"/user/logout"}>
                  <img src={logout} width="17" height="48" alt="로그아웃" />
                </Link>
              </li>
            )}
            {!loginState.email ? (
              <li>
                <Link to={"/user/join"}>
                  <img src={signup} width="23.5" alt="회원가입" />
                </Link>
              </li>
            ) : (
              <li>
                <Link to={`/user/mypage/${email}`}>
                  <img src={idcard} width="23.5" alt="마이페이지" />
                </Link>
              </li>
            )}
          </ul>
        </div>
      </div>
    </header>
  );
}

export default Header;
