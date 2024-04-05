import React, { useCallback, useEffect, useState } from "react";
import "../../styles/components/fixedMenu.scss";
import { useNavigate } from "react-router-dom";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";
import useCustomCartPage from "../../hooks/useCustomCartPage";
import ChatbotModal from "../chatbot/ChatbotModal";

function FixedMenu() {
  const { isLogin, loginState } = useCustomLoginPage();
  const { refreshCart, cartItems, changeCart } = useCustomCartPage();

  // 모달 상태를 관리할 상태 변수 추가
  const [isModalOpen, setIsModalOpen] = useState(false);

  // 모달이 열리고 닫히는 상태를 조절하는 함수
  const toggleModal = () => {
    setIsModalOpen(!isModalOpen);
  };

  //fixed menu
  useEffect(() => {
    const btn = document.querySelector(".btn-top");

    btn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });

  useEffect(() => {
    if (isLogin) {
      refreshCart();
    }
    // 총 금액 계산
  }, [isLogin]);

  //toggle
  const [isClosed, setIsClosed] = useState(false);

  const handleClose = () => {
    setIsClosed(true);
  };

  const handleOpen = () => {
    setIsClosed(false);
  };

  const navigate = useNavigate();

  const moveNoticeboardPage = useCallback(() => {
    navigate({ pathname: "/noticeboard/list" });
  });
  const moveShoppingBasket = useCallback(() => {
    navigate({ pathname: "/product/cart" });
  });

  return (
    <div className={`fmenu ${isClosed ? "closed" : ""}`}>
      <button className="btn-news" onClick={moveShoppingBasket}>
        장바구니 ({cartItems.length})
      </button>
      <button className="btn-news" onClick={moveNoticeboardPage}>
        공지사항
      </button>
      {/* 모달 열기 버튼에 onClick 이벤트 추가 */}
      <button className="btn-chat" onClick={toggleModal}>
        챗봇
      </button>
      <button className="btn-top">▲ Top</button>
      <button className="btn-close" onClick={handleClose}>
        접기
      </button>
      <button className="btn-open" onClick={handleOpen}>
        열기
      </button>
      {/* 모달 컴포넌트 추가 */}
      {isModalOpen && <ChatbotModal onClose={toggleModal} />}
    </div>
  );
}

export default FixedMenu;
