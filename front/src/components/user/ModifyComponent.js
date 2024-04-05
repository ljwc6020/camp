import { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { modifyUser, readUser } from "../../api/userApi";
import AlertModal from "../modal/AlertModal";
import { useNavigate } from "react-router-dom";
import * as Yup from "yup";

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

const ModifyComponent = () => {
  const [error, setError] = useState("");

  const loginInfo = useSelector((state) => state.loginSlice);

  const email = loginInfo.email;

  const [user, setUser] = useState({
    email: "",
    pw: "",
    nickname: "",
    phone: "",
    birth: "",
  });

  const navigate = useNavigate();
  const [errorMessage, setErrorMessage] = useState(""); // 에러 메시지 상태 추가

  const [result, setResult] = useState();

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        // 서버에서 사용자 정보 가져오기
        const userData = await readUser(email);
        const { pw, ...restInfo } = userData;

        // 사용자 정보 설정
        setUser(restInfo);
      } catch (error) {
        console.error("Error fetching user data:", error);
      }
    };

    if (email) {
      fetchUserData();
    }
  }, [email]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setError("");
    //비동기 방식의 문제점을 방지하기 위해 함수 방식을 사용
    setUser((prevUser) => ({
      ...prevUser,
      [name]: value,
    }));
  };

  const handleClickModify = async () => {
    try {
      // 전체 폼 데이터에 대한 유효성 검사 실행
      await validationSchema.validate(user, { abortEarly: false });
      // 유효성 검사 통과하면, 수정 요청 보내기
      await modifyUser(user);
      // 성공 처리
      setResult(true);
    } catch (error) {
      setResult(false); // 결과 상태를 실패로 설정
      if (error instanceof Yup.ValidationError) {
        // 유효성 검사 실패 시 첫 번째 에러 메시지를 표시
        setErrorMessage(error.errors[0]);
      }
    }
  };

  const closeModal = () => {
    setResult(null);
    navigate("/");
  };
  return (
    <div className="mt-6">
      {result ? (
        <AlertModal
          title={"회원정보"}
          content={"수정이 완료되었습니다"}
          callbackFn={closeModal}
        ></AlertModal>
      ) : (
        <></>
      )}
      <div>
        <div className="errorMessage">
          {errorMessage && (
            <div className="text-red-500 font-bold mb-4">{errorMessage}</div>
          )}
        </div>
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">E-mail</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md bg-gray-200"
            name="email"
            type="text"
            value={user.email}
            readOnly
          />
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">Password</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
            name="pw"
            type={"password"}
            placeholder="필수 입력"
            value={user.pw}
            onChange={handleChange}
          ></input>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">nickname</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
            name="nickname"
            type="text"
            value={user.nickname}
            onChange={handleChange}
          ></input>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">phone</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
            name="phone"
            type="text"
            value={user.phone}
            onChange={handleChange}
          ></input>
        </div>
      </div>
      <div className="flex justify-center">
        <div className="relative mb-4 flex w-full flex-wrap items-stretch">
          <div className="w-1/5 p-6 text-right font-bold">birth</div>
          <input
            className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
            name="birth"
            type="text"
            value={user.birth}
            onChange={handleChange}
          ></input>
        </div>
      </div>
      <div className="flex justify-center">
        {error && <div className="errorMessage">{error}</div>}
        {/* {error && <div className="text-red-500">{error}</div>} */}
        <div className="relative mb-4 flex w-full flex-wrap justify-end">
          <button
            type="button"
            className="rounded p-4 m-2 text-xl w-32 text-white bg-yellow-500"
            onClick={handleClickModify}
          >
            Modify
          </button>
        </div>
      </div>
    </div>
  );
};

export default ModifyComponent;
