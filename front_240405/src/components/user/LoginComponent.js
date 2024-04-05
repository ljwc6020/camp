import { useState } from "react";
import useCustomLogin from "../../hooks/useCustomLoginPage";
import KakaoLoginComponent from "./KakaoLoginComponent";
import "../../styles/user/loginPage.scss";
import { useNavigate } from "react-router-dom";

const initState = {
  email: "",
  pw: "",
};

const LoginComponent = () => {
  const [loginParam, setLoginParam] = useState({ ...initState });

  const { doLogin, moveToPath } = useCustomLogin();

  let navigate = useNavigate();

  const moveToResetPwPage = () => {
    navigate("/user/reset-pw");
  };

  const handleChange = (e) => {
    loginParam[e.target.name] = e.target.value;

    setLoginParam({ ...loginParam });
  };

  const handleClickLogin = (e) => {
    doLogin(loginParam) // loginSlice의 비동기 호출
      .then((data) => {
        console.log(data);
        if (data.error) {
          alert("이메일과 패스워드를 다시 확인하세요");
        } else {
          alert("로그인 성공");
          moveToPath("/");
        }
      });
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      handleClickLogin();
    }
  };

  return (
    <div className="loginWrap">
      <div className="loginTitle">
        {/* <div>로그인을 해주세요</div> */}
        <div>
          <span className="loginText">로그인</span>을 해주세요
        </div>
      </div>
      <div className="inputSection">
        <div className="email">
          <div>E-mail</div>
          <input
            name="email"
            type={"text"}
            value={loginParam.email}
            onChange={handleChange}
            onKeyPress={handleKeyPress}
          ></input>
        </div>

        <div className="password">
          <div>Password</div>
          <input
            name="pw"
            type={"password"}
            value={loginParam.pw}
            onChange={handleChange}
            onKeyPress={handleKeyPress}
          ></input>
        </div>
      </div>
      <div className="loginBottom">
        <div className="loginBtn">
          <button onClick={handleClickLogin}>LOGIN</button>
        </div>
        <div className="findBtn">
          <button className="findBtn" onClick={moveToResetPwPage}>
            비밀번호 찾기
          </button>
        </div>
        <KakaoLoginComponent />
      </div>
    </div>
  );
};

export default LoginComponent;
