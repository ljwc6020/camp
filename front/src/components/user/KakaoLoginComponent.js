import { Link } from "react-router-dom";
import { getKakaoLoginLink } from "../../api/kakaoApi";
import "../../styles/user/loginPage.scss";

const KakaoLoginComponent = () => {
  const link = getKakaoLoginLink();

  return (
    <div className="flex flex-col">
      <div className="text-center text-white">
        로그인시에 자동 가입처리 됩니다
      </div>
      <div className="flex justify-center  w-full">
        <Link to={link}>
          <button className="text-3xl text-center m-6 text-black font-extrabold w-3/4 bg-yellow-500 shadow-sm rounded p-2">
            KAKAO LOGIN
          </button>
        </Link>
      </div>
    </div>
  );
};

export default KakaoLoginComponent;
