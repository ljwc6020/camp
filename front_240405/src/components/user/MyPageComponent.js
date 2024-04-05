import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { Link } from "react-router-dom";
import { readUser } from "../../api/userApi"; // 사용자 정보를 가져오는 API 함수 임포트

const MyPageComponent = () => {
  const user = useSelector((state) => state.loginSlice); // 로그인 정보 가져오기
  const [userData, setUserData] = useState(null); // 사용자 정보 상태

  const email = user.email;

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        // 서버에서 사용자 정보 가져오기
        const userData = await readUser(email);
        // 사용자 정보 설정
        setUserData(userData);
      } catch (error) {
        console.error("Error fetching user data:", error);
      }
    };

    if (email) {
      fetchUserData();
    }
  }, [email]);

  return (
    <div className="myPageBundle">
      <span>My Page</span>
      <div className="InfoBundle">
        {/* 사용자 정보 표시 */}
        {userData && (
          <div className="userInfo">
            <div>E-mail: {userData.email}</div>
            <div>Nickname: {userData.nickname}</div>
            <div>Phone: {userData.phone}</div>
            <div>Birth: {userData.birth}</div>
          </div>
        )}
        <div className="btnBundle">
          <Link to={`/user/modify`}>
            <button>정보 수정</button>
          </Link>
          <Link to={`/user/remove/${email}`}>
            <button>회원 탈퇴</button>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default MyPageComponent;
