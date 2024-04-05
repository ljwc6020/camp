import React, { useState } from "react";
import axios from "axios"; // HTTP 통신을 위한 라이브러리
import "../../styles/chat/chatbot.scss";
import { TbMessageChatbot } from "react-icons/tb";
import styled from "styled-components";

const ChatbotComponent = () => {
  // 사용자 입력과 대화 내용을 관리하는 상태 변수들
  const [userInput, setUserInput] = useState(""); // 사용자 입력
  const [conversation, setConversation] = useState([
    // 초기 대화 내용 설정
    {
      speaker: "bot",
      message: "안녕하세요 캠프봇입니다! 무엇을 도와드릴까요?",
    },
  ]);

  // 사용자 입력 처리 함수
  const handleUserInput = (e) => {
    setUserInput(e.target.value);
  };

  // Dialogflow와의 통신 함수
  const sendMessageToDialogflow = async () => {
    try {
      // 사용자 입력을 포함하여 Dialogflow에 POST 요청 보내기
      const response = await axios.post(
        "http://localhost:8080/camp/send", // 백엔드 엔드포인트 URL
        { message: userInput },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      // Dialogflow로부터 받은 응답 처리
      let botMessage = response.data;

      // 각 조건문을 정규 표현식으로 수정하여 정확한 패턴을 찾도록 함
      // 왠진 몰라도 그냥 contain 쓰면못찾음
      if (/캠핑장/.test(botMessage)) {
        // 캠핑장 키워드가 포함된 경우 캠핑장 이동 버튼 추가
        botMessage = (
          <>
            {botMessage}{" "}
            {/* Dialogflow의 응답 메시지와 버튼 사이에 공백 추가 */}
            <button
              style={{
                display: "inline-block",
                padding: "8px 16px",
                fontSize: "16px",
                fontWeight: "bold",
                border: "none",
                cursor: "pointer",
                backgroundColor: "#007bff",
                color: "#fff",
                textDecoration: "none",
                transition: "all 0.3s ease",
              }}
              onMouseOver={(e) => (e.target.style.textDecoration = "underline")} // 마우스를 올릴 때 밑줄 추가
              onMouseOut={(e) => (e.target.style.textDecoration = "none")} // 마우스를 떼었을 때 밑줄 제거
              onClick={() =>
                (window.location.href = "http://localhost:3011/camping")
              }
            >
              캠핑장으로 이동
            </button>
          </>
        );
      }
      if (/쇼핑몰/.test(botMessage)) {
        // 쇼핑몰 키워드가 포함된 경우 쇼핑몰 이동 버튼 추가
        botMessage = (
          <>
            {botMessage}{" "}
            {/* Dialogflow의 응답 메시지와 버튼 사이에 공백 추가 */}
            <button
              style={{
                display: "inline-block",
                padding: "8px 16px",
                fontSize: "16px",
                fontWeight: "bold",
                border: "none",
                cursor: "pointer",
                backgroundColor: "#007bff",
                color: "#fff",
                textDecoration: "none",
                transition: "all 0.3s ease",
              }}
              onMouseOver={(e) => (e.target.style.textDecoration = "underline")} // 마우스를 올릴 때 밑줄 추가
              onMouseOut={(e) => (e.target.style.textDecoration = "none")} // 마우스를 떼었을 때 밑줄 제거
              onClick={() =>
                (window.location.href = "http://localhost:3011/product/list")
              }
            >
              쇼핑몰로 이동
            </button>
          </>
        );
      }
      if (/공지사항/.test(botMessage)) {
        // 공지사항 키워드가 포함된 경우 공지사항 이동 버튼 추가
        botMessage = (
          <>
            {botMessage}{" "}
            {/* Dialogflow의 응답 메시지와 버튼 사이에 공백 추가 */}
            <button
              style={{
                display: "inline-block",
                padding: "8px 16px",
                fontSize: "16px",
                fontWeight: "bold",
                border: "none",
                cursor: "pointer",
                backgroundColor: "#007bff",
                color: "#fff",
                textDecoration: "none",
                transition: "all 0.3s ease",
              }}
              onMouseOver={(e) => (e.target.style.textDecoration = "underline")} // 마우스를 올릴 때 밑줄 추가
              onMouseOut={(e) => (e.target.style.textDecoration = "none")} // 마우스를 떼었을 때 밑줄 제거
              onClick={() =>
                (window.location.href =
                  "http://localhost:3011/noticeboard/list")
              }
            >
              공지사항으로 이동
            </button>
          </>
        );
      }
      // "상품번호"가 포함된 경우 상품 정보로 이동하는 링크 생성
      // 마찬가지로 정규식으로 나누고 상품 번호의 번호만 추출
      if (/상품번호:/.test(botMessage)) {
        const productNumberRegex = /상품번호: (\d+)/;
        const productNumberMatch = botMessage.match(productNumberRegex);
        if (productNumberMatch) {
          const productNumber = productNumberMatch[1]; // 우리가쓸건 그 중에서도 두번째, 숫자만
          botMessage = (
            <>
              {botMessage}{" "}
              {/* Dialogflow의 응답 메시지와 버튼 사이에 공백 추가 */}
              <button
                style={{
                  display: "inline-block",
                  padding: "8px 16px",
                  fontSize: "16px",
                  fontWeight: "bold",
                  border: "none",
                  cursor: "pointer",
                  backgroundColor: "#007bff",
                  color: "#fff",
                  textDecoration: "none",
                  transition: "all 0.3s ease",
                }}
                onMouseOver={(e) =>
                  (e.target.style.textDecoration = "underline")
                } // 마우스를 올릴 때 밑줄 추가
                onMouseOut={(e) => (e.target.style.textDecoration = "none")} // 마우스를 떼었을 때 밑줄 제거
                onClick={() =>
                  (window.location.href = `http://localhost:3011/product/read/${productNumber}`)
                }
              >
                해당 상품으로 이동
              </button>
            </>
          );
        }
      }

      // 대화 기록 업데이트: 사용자 입력과 봇의 응답 메시지를 추가
      setConversation([
        ...conversation, // 기존 대화 내용을 유지한 채로 새로운 대화 추가
        { speaker: "user", message: userInput }, // 사용자 입력 추가
        { speaker: "bot", message: botMessage }, // 봇의 응답 메시지 추가
      ]);
    } catch (error) {
      // 오류 처리: Dialogflow와의 통신 중 에러가 발생한 경우
      console.error("Error sending message to Dialogflow:", error);
    }
  };

  // 폼 제출 핸들러 함수
  const handleSubmit = async (e) => {
    e.preventDefault(); // 폼의 기본 동작(페이지 새로고침) 방지
    // 사용자 입력을 Dialogflow에 전송
    await sendMessageToDialogflow();
    // 사용자 입력 초기화
    setUserInput("");
  };

  return (
    <div className="chat-container">
      <div className="chatbot-name">Chatbot</div>
      <div className="chat">
        {/* 대화 내용 출력: conversation 배열을 사용하여 반복 렌더링 */}
        {conversation.map((item, index) => (
          <div key={index} className={`message ${item.speaker}`}>
            {item.speaker === "bot" && (
              <BotHeader>
                <TbMessageChatbot />
                <div className="bot-header-name">Chatbot</div>
              </BotHeader>
            )}
            {item.message} {/* 대화 내용 출력 */}
          </div>
        ))}
      </div>
      <div className="user-input">
        {/* 사용자 입력 폼 */}
        <form onSubmit={handleSubmit} className="user-input-form">
          {/* 사용자 입력을 받는 입력 필드 */}
          <input type="text" value={userInput} onChange={handleUserInput} />
          {/* 사용자 입력을 전송하는 버튼 */}
          <button type="submit">Send</button>
        </form>
      </div>
    </div>
  );
};

const BotHeader = styled.div`
  display: flex;
  align-items: center;
  height: 20px;
  margin-bottom: 4px;
  .logo {
    width: 20px;
    height: 20px;
    margin-right: 4px;
  }
  .bot-header-name {
    font-size: 12px;
    color: #666;
  }
`;

export default ChatbotComponent;
