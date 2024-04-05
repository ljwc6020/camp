import React, { useEffect, useRef, useState } from "react";
import { loadPaymentWidget, ANONYMOUS } from "@tosspayments/payment-widget-sdk";
import { useLocation, useNavigate } from "react-router-dom";

const generateOrderId = () => `order_${Date.now()}`;

export function CheckoutPage() {
  const paymentWidgetRef = useRef(null);
  const location = useLocation();
  const navigate = useNavigate();
  const [selectedProducts, setSelectedProducts] = useState([]); // 선택된 상품의 ID를 저장할 상태

  const handleSelectProduct = (productId) => {
    // 이미 선택된 상품인지 확인하고 선택된 상품 목록을 업데이트합니다.
    const isSelected = selectedProducts.includes(productId);
    if (isSelected) {
      setSelectedProducts(selectedProducts.filter((id) => id !== productId));
    } else {
      setSelectedProducts([...selectedProducts, productId]);
    }
  };

  const { productName, productPrice, productId, quantity } =
    location.state || {};

  useEffect(() => {
    (async () => {
      const paymentWidget = await loadPaymentWidget(
        "본인의 키 입력",
        ANONYMOUS
      );

      paymentWidgetRef.current = paymentWidget;

      paymentWidget.renderPaymentMethods(
        "#payment-method",
        { value: productPrice * quantity },
        { variantKey: "DEFAULT" }
      );
      paymentWidget.renderAgreement("#agreement", { variantKey: "DEFAULT" });
    })();
  }, [productPrice, quantity]);

  const handlePayment = async () => {
    if (!paymentWidgetRef.current) {
      console.error("결제 위젯이 로드되지 않았습니다.");
      return;
    }

    try {
      const response = await paymentWidgetRef.current.requestPayment({
        orderId: generateOrderId(),
        orderName: productName || "Default Product Name",
        customerName: "고객 이름", // 고객 이름 동적 할당
        customerEmail: "customer@example.com", // 고객 이메일 동적 할당
        amount: productPrice * quantity,
        successUrl: window.location.origin + "/payment/success", // 성공 시 리디렉션할 경로
        failUrl: window.location.origin + "/payment/fail", // 실패 시 리디렉션할 경로
      });

      // 결제 성공 시 success 페이지로, 실패 시 fail 페이지로 리디렉션
      // 주의: 실제로 이 부분은 결제 위젯에 의해 처리되므로 아래 코드는 예시일 뿐입니다.
      if (response.success) {
        // 결제가 성공하면 선택된 상품들을 장바구니에서 제거
        selectedProducts.forEach((productId) => {
          // 각 상품을 삭제하는 로직을 구현하세요.
        });
        navigate("/payment/success");
      } else {
        navigate("/payment/fail");
      }
    } catch (error) {
      console.error("결제 처리 중 오류 발생:", error);
      navigate("/payment/fail"); // 에러 발생 시 실패 페이지로 리디렉션
    }
  };

  const handleClickQty = (qty) => {
    // 여기에 선택된 상품을 장바구니에서 삭제하는 로직을 추가하세요.
  };

  return (
    <div className="wrapper w-100">
      <div className="max-w-540 w-100">
        <div id="payment-method" className="w-100" />
        <div id="agreement" className="w-100" />
        <div className="btn-wrapper w-100">
          <button className="btn primary w-100" onClick={handlePayment}>
            결제하기
          </button>
        </div>
      </div>
    </div>
  );
}
