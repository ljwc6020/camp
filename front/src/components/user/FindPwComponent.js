import React, { useState } from "react";
import { sendEmail } from "../../api/userApi";
import { useNavigate } from "react-router-dom";

const FindPwComponent = () => {
  const [email, setEmail] = useState("");
  const navigate = useNavigate();

  const handleEmailChange = (e) => {
    setEmail(e.target.value);
  };

  const handleSubmit = async () => {
    if (!email) {
      alert("이메일을 입력해주세요.");
      return;
    }

    try {
      // 'sendEmail' 함수를 사용하여 비밀번호 재설정 요청을 보냅니다.
      await sendEmail(email);
      alert("임시 비밀번호를 발송했습니다. 이메일을 확인해주세요.");
      // 비밀번호 재설정 요청이 성공적으로 처리된 후, 원하는 경로로 네비게이션 할 수 있습니다.
      navigate("/user/login");
    } catch (error) {
      if (error.response) {
        const { status, data } = error.response;
        if (status === 404) {
          alert("등록되지 않은 이메일입니다. 다시 확인해주세요.");
        } else {
          alert(
            data.message ||
              "비밀번호 재설정 요청에 실패했습니다. 다시 시도해주세요."
          );
        }
      }
    }
  };

  return (
    <div className="findWrap">
      <div className="findTitle">
        <div>
          <span className="findText">이메일</span>을 입력해주세요
        </div>
      </div>
      <div className="inputSection">
        <input type="email" value={email} onChange={handleEmailChange} />
      </div>

      <div className="findBottom">
        <button onClick={handleSubmit}>임시비밀번호 발송</button>
      </div>
    </div>
  );
};

export default FindPwComponent;
