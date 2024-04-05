import React, { useState } from "react";
import axios from "axios"; // HTTP 통신을 위한 라이브러리
import ChatbotComponent from "./ChatbotComponent"; // 챗봇 컴포넌트 import
import "../../styles/chat/chatbot.scss"; // 변경된 경로에 맞게 수정

const ChatbotModal = ({ onClose }) => {
  const [userInput, setUserInput] = useState("");
  const [botResponse, setBotResponse] = useState("");

  // 사용자 입력 처리
  const handleUserInput = (e) => {
    setUserInput(e.target.value);
  };

  // Dialogflow와의 통신
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
      setBotResponse(response.data);
    } catch (error) {
      console.error("Error sending message to Dialogflow:", error);
    }
  };

  // 폼 제출 핸들러
  const handleSubmit = (e) => {
    e.preventDefault();
    // 사용자 입력을 Dialogflow에 전송
    sendMessageToDialogflow();
    // 사용자 입력 초기화
    setUserInput("");
  };

  return (
    <div className="chat-modal-overlay" onClick={onClose}>
      <div className="chat-modal-content" onClick={(e) => e.stopPropagation()}>
        {/* 챗봇 컴포넌트 */}
        <ChatbotComponent
          userInput={userInput}
          botResponse={botResponse}
          handleUserInput={handleUserInput}
          handleSubmit={handleSubmit}
        />
      </div>
    </div>
  );
};

export default ChatbotModal;
