import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import useCustomCartPage from "../../hooks/useCustomCartPage"; // 장바구니 커스텀 훅 가져오기
import useCustomLoginPage from "../../hooks/useCustomLoginPage"; // 로그인 상태를 가져오기 위한 훅

export function PaymentSuccessPage() {
  const navigate = useNavigate();
  const { cartItems, changeCart, refreshCart } = useCustomCartPage(); // 장바구니 관련 함수 가져오기
  const { loginState } = useCustomLoginPage(); // 로그인 상태 가져오기

  useEffect(() => {
    console.log("결제 성공 페이지에 도착했습니다.");

    // 로그인 상태 정보 출력
    console.log("로그인 상태:", loginState);

    // 결제 성공 페이지에 도착하면 실행되는 함수
    const clearSelectedItems = async () => {
      console.log("현재 장바구니 아이템들:", cartItems);

      for (const item of cartItems) {
        console.log(`아이템 삭제 중...: ${item.cino}`);
        await changeCart({
          email: loginState.email, // loginState에서 현재 로그인한 사용자의 이메일 주소를 가져옴
          pno: item.pno,
          cino: item.cino,
          qty: 0, // 수량을 0으로 설정하여 장바구니에서 해당 아이템을 제거
        });
      }
      refreshCart(); // 장바구니를 새로고침
      console.log("장바구니를 새로고침했습니다.");
    };

    clearSelectedItems();
  }, [cartItems]);

  useEffect(() => {
    // 3초 후에 상품 리스트 페이지로 리다이렉션
    const timer = setTimeout(() => {
      console.log("상품 리스트 페이지로 리다이렉션합니다.");
      navigate("/product/list?page=1&size=12");
    }, 3000);

    return () => {
      console.log("타이머를 정리합니다.");
      clearTimeout(timer);
    };
  }, [navigate]);

  return (
    <div
      className="payment-success-container"
      style={{ padding: "20px", textAlign: "center" }}
    >
      <h1>결제가 완료되었습니다!</h1>
      <p>고객님의 주문이 성공적으로 처리되었습니다. 주문해주셔서 감사합니다.</p>
      <p>잠시 후 상품 목록 페이지로 이동합니다...</p>
    </div>
  );
}
