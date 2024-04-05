import React from "react";
import CartComponent_p from "../../../components/product/cart/CartComponent_p";
import "../../../styles/pages/cartPage.scss";

const CartPage_p = () => {
  return (
    <div className="cart_index">
      <div className="cart_title">
        <ul>
          <li>- 장바구니 -</li>
          <li></li>
        </ul>
      </div>
      <div className="cart_section">
        <CartComponent_p />
      </div>
    </div>
  );
};

export default CartPage_p;
