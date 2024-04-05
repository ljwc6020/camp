import React from "react";

const CartModal = ({ closeCartModal, moveCartPage }) => {
  return (
    <div className="fixed top-0 left-0 z-[1055] flex h-full w-full justify-center items-center bg-black bg-opacity-50">
      <div className="bg-black bg-opacity-50 w-1/4 rounded mt-10 mb-10 px-6 min-w-[400px]">
        <div className="p-6 text-center text-white py-6">
          상품이 장바구니에 담겼습니다.
          <br />
          장바구니로 이동하시겠습니까?
        </div>
        <div className="flex justify-center space-x-4">
          <button
            className="bg-yellow-500 text-white px-6 py-3 rounded mt-4 mb-4 w-2/5"
            onClick={moveCartPage}
          >
            이동
          </button>
          <button
            className="bg-yellow-500 text-white px-6 py-3 rounded mt-4 mb-4 w-2/5"
            onClick={closeCartModal}
          >
            취소
          </button>
        </div>
      </div>
    </div>
  );
};

export default CartModal;
