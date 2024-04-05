import { useDispatch, useSelector } from "react-redux";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { removeUser } from "../../api/userApi";
import { logout } from "../../slices/loginSlice";

const RemoveComponent = () => {
  const [result, setResult] = useState(false);
  const [error, setError] = useState(null);
  const [isConfirmationOpen, setIsConfirmationOpen] = useState(false);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Redux 스토어에서 현재 로그인한 사용자 정보를 가져옴
  const user = useSelector((state) => state.loginSlice);
  const email = user.email;

  const handleClickRemove = () => {
    // 알림 창 열기
    setIsConfirmationOpen(true);
  };

  const handleConfirmRemove = async () => {
    try {
      if (!email) {
        throw new Error("로그인 정보가 존재하지 않습니다.");
      }

      // 회원 탈퇴 요청 보내기
      await removeUser(email).then(() => {
        // removeUser 호출 시 객체로 전달
        setResult(true);
        dispatch(logout()); // 회원 탈퇴 성공 후 로그아웃 처리
        navigate("/"); // 홈 화면으로 이동
      });
    } catch (error) {
      console.error("회원 탈퇴 실패:", error);
      setError("회원 탈퇴에 실패했습니다."); // 사용자에게 오류 메시지 표시
    }
  };

  const handleCancelRemove = () => {
    // 알림 창 닫기
    setIsConfirmationOpen(false);
  };

  return (
    <div className="removeComponentWrap">
      {result && <div className="text-red-500 font-bold">회원 탈퇴 성공</div>}

      {error && <p className="text-red-500">{error}</p>}
      <button className="removeBtn" onClick={handleClickRemove}>
        탈퇴하기
      </button>

      {isConfirmationOpen && (
        <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-50 flex justify-center items-center">
          <div className="bg-white p-6 rounded-lg shadow-lg">
            <div className="text-xl font-bold mb-4">회원 탈퇴 확인</div>
            <div>정말 탈퇴하시겠습니까?</div>
            <div className="flex justify-end mt-4">
              <button
                onClick={handleConfirmRemove}
                className="bg-yellow-500 text-white py-2 px-4 rounded mr-2"
              >
                확인
              </button>
              <button
                onClick={handleCancelRemove}
                className="bg-gray-400 text-white py-2 px-4 rounded"
              >
                취소
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RemoveComponent;
