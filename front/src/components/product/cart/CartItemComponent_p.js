import { useState } from "react";
import { API_SERVER_HOST } from "../../../api/userApi";
import "../../../styles/pages/cartPage.scss";
import { formatNumber } from "../../../util/formatNumberUtil";
import { IoCloseOutline } from "react-icons/io5";

const host = API_SERVER_HOST;

const CartItemComponent_p = ({
  cino,
  pname,
  pdesc,
  price,
  pno,
  qty,
  imageFile,
  changeCart,
  email,
  onSelect, // 부모 컴포넌트로부터 받은 아이템 선택/해제를 처리하는 함수
  isSelected, // 부모 컴포넌트로부터 받은 현재 아이템의 선택 상태
}) => {
  const [quantity, setQuantity] = useState(qty);

  const handleClickQty = (amount) => {
    const newQty = qty + amount; // 변경된 수량 계산
    if (newQty > 0) {
      changeCart({ email, cino, pno, qty: newQty }); // 변경된 수량을 서버로 전달하여 장바구니 업데이트
    } else {
      // 수량이 0 이하로 내려가지 않도록 방지
      alert("수량은 1 이상이어야 합니다.");
    }
  };

  const handleDelete = () => {
    const newQty = 0; // 변경된 수량 계산

    changeCart({ email, cino, pno, qty: newQty }); // 변경된 수량을 서버로 전달하여 장바구니 업데이트
  };

  const handleQuantityInput = (event) => {
    const inputQuantity = parseInt(event.target.value, 10); // 입력값을 숫자로 변환
    if (!isNaN(inputQuantity) && inputQuantity >= 0) {
      setQuantity(inputQuantity); // 내부 상태 업데이트
      changeCart({ email, cino, pno, qty: inputQuantity }); // 부모 컴포넌트의 상태 또는 전역 상태 업데이트 함수 호출
    } else {
      // 유효하지 않은 입력이 들어오면 수량을 0으로 설정
      alert("수량은 1 이상이어야 합니다.");
    }
  };

  return (
    <div className="cartItem-group">
      <div className="cartItem-area">
        <div className="cartItem-wrap cartItemSelect">
          {/* 체크박스 추가 */}
          <input
            type="checkbox"
            checked={isSelected}
            onChange={() => onSelect(cino)} // 체크박스 상태 변경 시 onSelect 함수 호출
          />
        </div>

        <div className="cartItem-wrap cartItemImg">
          <img src={`${host}/api/products/view/s_${imageFile}`} alt={pname} />
        </div>

        <div className="cartItem-wrap cartItemPname">
          <div className="pname">{pname}</div>
        </div>
        <div className="cartItem-wrap cartItemPrice">
          {formatNumber(price)} 원
        </div>
        <div className="cartItem-wrap cartItemQty">
          <div className="cartItem-box">
            <button
              className="quantity_button"
              onClick={() => handleClickQty(-1)}
            >
              -
            </button>
            <input
              type="text"
              className="quantity_display"
              value={qty}
              onChange={handleQuantityInput}
              min="1" // 최소 수량을 1로 설정합니다.
            />
            <button
              className="quantity_button"
              onClick={() => handleClickQty(1)}
            >
              +
            </button>
          </div>
        </div>
        <div className="cartItem-wrap cartItemTprice">
          {formatNumber(qty * price)} 원
        </div>
        <div className="cartItem-wrap cartItemDelete">
          <button onClick={handleDelete}>
            <IoCloseOutline />
          </button>
        </div>
      </div>
    </div>
  );
};
export default CartItemComponent_p;
