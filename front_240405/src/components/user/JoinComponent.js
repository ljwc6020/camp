import React, { useEffect, useState } from "react";
import { joinUser } from "../../api/userApi"; // loginPost 함수 추가
import AlertModal from "../modal/AlertModal";
import useCustomLogin from "../../hooks/useCustomLoginPage";
import * as Yup from "yup";

const initState = {
  email: "",
  pw: "",
  nickname: "",
  phone: "",
  birth: "",
};

// 전체 폼에 대한 유효성 검사 스키마
const validationSchema = Yup.object({
  email: Yup.string()
    .email("유효한 이메일을 입력하세요.")
    .required("이메일은 필수 항목입니다."),
  pw: Yup.string()
    .matches(
      /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{5,}$/,
      "비밀번호는 영문자, 숫자, 특수문자를 모두 포함하여 5자 이상이어야 합니다."
    )
    .required("비밀번호는 필수 항목입니다."),
  nickname: Yup.string().required("닉네임은 필수 항목입니다."),
  phone: Yup.string()
    .matches(/^\d{11}$/, "핸드폰 번호는 11자리여야 합니다.")
    .required("전화번호는 필수 항목입니다."),
  birth: Yup.string()
    .matches(/^\d{8}$/, "생년월일은 8자리여야 합니다.")
    .required("생년월일은 필수 항목입니다."),
});

const JoinComponent = () => {
  const [user, setUser] = useState(initState);
  const [result, setResult] = useState(false); // 성공 여부를 저장할 상태 추가
  const [errorMessage, setErrorMessage] = useState(""); // 에러 메시지 상태 추가

  const { moveToLogin } = useCustomLogin();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setUser({ ...user, [name]: value });
  };

  const handleClickJoin = async (e) => {
    e.preventDefault();

    try {
      // 전체 폼 데이터에 대한 유효성 검사 실행
      await validationSchema.validate(user, { abortEarly: false });
      // 유효성 검사 통과하면, 회원가입 요청 보내기
      await joinUser(user);
      // 성공 처리
      setResult(true);
    } catch (error) {
      setResult(false); // 결과 상태를 실패로 설정
      if (error instanceof Yup.ValidationError) {
        // 유효성 검사 실패 시 첫 번째 에러 메시지를 표시
        setErrorMessage(error.errors[0]);
      } else if (
        error.response &&
        error.response.data &&
        error.response.data.status === "already_exists"
      ) {
        // 이미 존재하는 아이디인 경우의 에러 메시지
        setErrorMessage("이미 존재하는 아이디입니다.");
      } else {
        // 그 외 서버 에러 처리
        setErrorMessage("회원가입 처리 중 오류가 발생했습니다.");
      }
    }
  };

  const closeModal = () => {
    setResult(false); // 모달 닫을 때 결과 상태 초기화
    setUser(initState); // 유저 정보 초기화
    moveToLogin(); // 회원가입 성공 후 로그인 페이지로 이동
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      handleClickJoin(e);
    }
  };

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Enter" && result) {
        closeModal();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    // 컴포넌트가 언마운트될 때 이벤트 리스너를 정리
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [result]);

  return (
    <div className="joinComponentWrap">
      {/* 회원가입 성공 시에만 결과 모달 표시 */}
      {result && (
        <AlertModal
          title={"회원가입 성공"}
          content={"회원가입 성공"}
          callbackFn={closeModal}
        ></AlertModal>
      )}
      <span>회원가입</span>

      <div>
        <div className="errorMessage">
          {errorMessage && (
            <div className="text-red-500 font-bold mb-4">{errorMessage}</div>
          )}
        </div>
        <div>
          <form onSubmit={handleClickJoin}>
            <ul className="joinUl">
              <li>
                E-mail:{" "}
                <input
                  className="w-full  p-3 rounded-r border border-solid border-neutral-500 shadow-md"
                  name="email"
                  placeholder="ex) kms@naver.com"
                  type="text"
                  value={user.email}
                  onChange={handleChange}
                  required
                />
              </li>
              <li>
                Password:{" "}
                <input
                  className="w-full p-3 rounded-r border border-solid border-neutral-500 shadow-md"
                  name="pw"
                  type="password"
                  placeholder="영문자, 숫자, 특수문자를 모두 포함하여 5자 이상이어야 합니다."
                  value={user.pw}
                  onChange={handleChange}
                  required
                />
              </li>
              <li>
                Nickname:{" "}
                <input
                  className="w-full p-3 rounded-r border border-solid border-neutral-500 shadow-md"
                  name="nickname"
                  type="text"
                  value={user.nickname}
                  onChange={handleChange}
                  required
                />
              </li>
              <li>
                Phone:{" "}
                <input
                  className="w-full p-3 rounded-r border border-solid border-neutral-500 shadow-md"
                  name="phone"
                  placeholder="- 없이 숫자만 입력해주세요"
                  type="tel"
                  value={user.phone}
                  onChange={handleChange}
                  required
                />
              </li>
              <li>
                Birth:{" "}
                <input
                  className="w-full p-3 rounded-r border border-solid border-neutral-500 shadow-md"
                  name="birth"
                  placeholder="ex) - 없이 생년월일8자리 입력해주세요"
                  type="text"
                  value={user.birth}
                  onChange={handleChange}
                  onKeyPress={handleKeyPress}
                  required
                />
              </li>
              <li className="btnLi">
                <button type="submit" className="joinBtn">
                  제출
                </button>
              </li>
            </ul>
          </form>
        </div>
      </div>
    </div>
  );
};

export default JoinComponent;
