package com.camp.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

// Lombok 라이브러리를 사용하여 기본적인 getter/setter, toString, equals, hashCode 메서드를 자동으로 생성합니다.
@Data
// Lombok 라이브러리를 사용하여 Builder 패턴을 구현합니다. 객체 생성 시 안전성과 가독성을 높입니다.
@Builder
// 모든 필드 값을 매개변수로 받는 생성자를 자동으로 생성합니다.
@AllArgsConstructor
// 기본 생성자를 자동으로 생성합니다.
@NoArgsConstructor
public class ProductQnaDTO {
    private Long qno;  // Q&A의 고유 식별자
    private Long pno;  // 상품의 고유 식별자
    private String question;  // Q&A 질문 내용
    private String answer;  // Q&A 답변 내용
    private String authorName;  // Q&A를 작성한 사용자의 이름
    private boolean answered;   // Q&A 답변 여부

    // JSON으로 변환될 때 지정된 포맷으로 날짜를 변환합니다. 답변 작성 시간을 표시합니다.
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDateTime answeredAt;

    // JSON으로 변환될 때 지정된 포맷으로 날짜를 변환합니다. 질문 작성 시간을 표시합니다.
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDateTime askedAt;

    // 첨부된 파일 목록. Q&A에 파일을 첨부할 경우 사용됩니다.
    @Builder.Default
    private List<MultipartFile> files = new ArrayList<>();

    // 업로드된 파일의 이름 목록. 파일이 업로드된 후, 저장된 파일의 이름을 추적합니다.
    @Builder.Default
    private List<String> uploadFileNames = new ArrayList<>();

    // 질문 내용과 작성자 이름만을 인자로 받는 특수 생성자. 특정 시나리오에서만 사용될 수 있습니다.
    public ProductQnaDTO(String question, String authorName, boolean answered) {
        this.question = question;
        this.authorName = authorName;
        this.answered = answered;
    }

}
