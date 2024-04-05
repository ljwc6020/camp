import useCustomLogin from "../../hooks/useCustomLoginPage";

const LogoutComponent = () => {
  const { doLogout, moveToPath } = useCustomLogin();

  const handleClickLogout = () => {
    doLogout();
    alert("로그아웃되었습니다.");
    moveToPath("/");
  };

  return (
    <div className="logOutBg">
      <div className="logOutTitle">
        <div>
          <span>로그아웃</span>을 원하시면
        </div>
        <div>
          아래 <span>로그아웃</span> 버튼을 눌러주세요
        </div>
      </div>

      <button onClick={handleClickLogout}>LOGOUT</button>
    </div>
  );
};

export default LogoutComponent;
