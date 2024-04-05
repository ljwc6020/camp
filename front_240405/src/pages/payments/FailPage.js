import { useSearchParams, useNavigate } from "react-router-dom";

export function FailPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate(); // useNavigate 훅 사용 준비
  const errorCode = searchParams.get("code");
  const errorMessage = searchParams.get("message");

  // "다시 테스트하기" 버튼 클릭 시 실행될 함수
  const handleRetry = () => {
    navigate("/product/list"); // 현재 탭에서 상품 리스트 페이지로 이동
  };

  return (
    <div className="wrapper w-100">
      <div className="flex-column align-center w-100 max-w-540">
        <img
          src="https://static.toss.im/lotties/error-spot-apng.png"
          width="120"
          height="120"
        />
        <h2 className="title">결제를 실패했어요</h2>
        <div className="response-section w-100">
          <div className="flex justify-between">
            <span className="response-label">실패요청</span>
            <span id="error-code" className="response-text">
              {errorCode}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="response-label">다시 시도하세요</span>
            <span id="error-message" className="response-text">
              {errorMessage}
            </span>
          </div>
        </div>

        <div className="w-100 button-group">
          {/* <a> 태그 대신 <button> 태그를 사용하여 리디렉션 처리 */}
          <button className="btn" onClick={handleRetry}>
            다시 테스트하기
          </button>
          <div className="flex" style={{ gap: "16px" }}>
            <a
              className="btn w-100"
              href="https://docs.tosspayments.com/reference/error-codes"
              target="_blank"
              rel="noreferrer noopener"
            >
              에러코드 문서보기
            </a>
            <a
              className="btn w-100"
              href="https://techchat.tosspayments.com"
              target="_blank"
              rel="noreferrer noopener"
            >
              실시간 문의하기
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
