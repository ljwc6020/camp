import React, { useEffect, useState } from "react";
import CartItemComponent_p from "./CartItemComponent_p";
import useCustomLoginPage from "../../../hooks/useCustomLoginPage";
import useCustomCartPage from "../../../hooks/useCustomCartPage";
import "../../../styles/pages/cartPage.scss";
import { formatNumber } from "../../../util/formatNumberUtil";
import { useNavigate } from "react-router-dom";

const CartComponent_p = () => {
  const { isLogin, loginState } = useCustomLoginPage();
  const { refreshCart, changeCart, cartItems } = useCustomCartPage();
  const [selectedItems, setSelectedItems] = useState([]); // 선택한 상품들의 배열
  const [totalAmount, setTotalAmount] = useState(0); // 총 금액을 저장할 상태
  const navigate = useNavigate();

  // 이전 코드는 체크박스를 클릭해야 장바구니 목록값을 가져와서 총 가격을 결정해줬는대
  // 체크 하기전에는, 장바구니 아이템이 없는게되버려서 기본값으로 못줬던거 같습니다.
  // 그냥 로그인되있으면 한꺼번에 장바구니 목록 불러와버리니까 시작할때 바로 체크 됩니다.
  // 즉 isSelected 는 장바구니의 아이템이 있으면 알아서 체크되야 하는대, 왠지모르게
  // 시작할때 그냥 장바구니 아이템을 만들어버려서 해결했습니다.
  useEffect(() => {
    if (isLogin) {
      setSelectedItems(cartItems.map((item) => item.cino));
      refreshCart();
    }
  }, [isLogin]);

  // 선택된 상품들의 가격 합산 함수
  const calculateTotalAmount = () => {
    let total = 0;
    selectedItems.forEach((cino) => {
      const selectedItem = cartItems.find((item) => item.cino === cino);
      if (selectedItem) {
        total += selectedItem.price * selectedItem.qty;
      }
    });
    return total;
  };

  const deleteBascket = () => {
    selectedItems.forEach((cino) => {
      const selectedItem = cartItems.find((item) => item.cino === cino);
      if (selectedItem) {
        const { pno, cino } = selectedItem;
        changeCart({ email: loginState.email, pno, cino, qty: 0 }); // 수량을 0으로 설정하여 삭제
      }
    });
  };

  const handleClickPayment = () => {
    if (selectedItems.length === 0) {
      alert("상품을 선택해주세요.");
      return;
    }
    const totalPrice = calculateTotalAmount();
    navigate("/payment", {
      state: {
        productName: "asd",
        productPrice: totalPrice,
        productId: 5,
        quantity: 1,
      },
    });
    window.location.reload();
    deleteBascket();

    console.log(selectedItems);
  };

  const handleItemSelect = (cino) => {
    // 선택한 상품들의 상태 업데이트
    if (selectedItems.includes(cino)) {
      setSelectedItems(selectedItems.filter((item) => item !== cino)); // 이미 선택한 상품인 경우 선택 취소
    } else {
      setSelectedItems([...selectedItems, cino]); // 새로운 상품을 선택한 경우 추가
    }
  };

  useEffect(() => {
    if (isLogin) {
      refreshCart();
    }
  }, [isLogin]); // 로그인 상태가 변경될 때만 refreshCart를 호출

  useEffect(() => {
    // 총 금액 계산
    const total = calculateTotalAmount();
    setTotalAmount(total); // 계산된 총 금액을 상태로 저장
  }, [cartItems, selectedItems]);

  return (
    <div className="cart-group basketdiv">
      {isLogin ? (
        <div className="cart-area">
          <div className="cart-wrap itemWrap">
            <div className="cart-box cartLength">
              장바구니 상품 ( {cartItems.length} )
            </div>
            <ul className="cart-box cartMenu">
              <li>선택</li>
              <li>사진</li>
              <li>상품명</li>
              <li>판매가</li>
              <li>수량</li>
              <li>금액</li>
              <li>취소</li>
            </ul>
            <ul>
              {cartItems.map((item) => (
                <CartItemComponent_p
                  {...item}
                  key={item.cino}
                  changeCart={changeCart}
                  email={loginState.email}
                  onSelect={() => handleItemSelect(item.cino)} // 상품 선택 이벤트 핸들러 추가
                  isSelected={selectedItems.includes(item.cino)} // 선택 상태 전달
                />
              ))}
            </ul>
          </div>
          <div className="cart-wrap cartTotal">
            <div className="cart-box cartTprice">
              <div>총 상품 금액</div>
              <div>{formatNumber(totalAmount)}원</div>
            </div>
            <div className="cart-box cartPayment">
              <button
                type="button"
                className="cart_paymentBtn"
                onClick={handleClickPayment}
              >
                상품주문
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="empty">로그인이 필요합니다.</div>
      )}
    </div>
  );
};

export default CartComponent_p;
