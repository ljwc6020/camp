package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

// Lombok 라이브러리의 어노테이션을 사용하여 getter, setter, toString 등의 메서드를 자동으로 생성합니다.
@Data
// JPA 엔티티 클래스임을 나타냅니다. 이 클래스의 인스턴스는 데이터베이스 테이블의 행과 매핑됩니다.
@Entity
// 데이터베이스 내의 해당 엔티티에 매핑될 테이블의 이름을 지정합니다.
@Table(name = "tbl_product_qna")
// 기본 생성자를 자동으로 생성합니다.
@NoArgsConstructor
// 모든 필드 값을 파라미터로 받는 생성자를 자동으로 생성합니다.
@AllArgsConstructor
// 빌더 패턴을 구현하는 메서드를 자동으로 생성합니다. 객체 생성 시 안전성과 가독성을 높입니다.
@Builder
public class ProductQna {

    // Q&A의 고유 번호를 나타내는 필드. 데이터베이스에서 자동으로 생성되는 ID 값입니다.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long qno;

    // Q&A가 속한 상품을 나타냅니다. 'Product' 엔티티와 다대일 관계를 형성합니다.
    @ManyToOne(fetch = FetchType.LAZY)
    private Product product;

    // Q&A 질문 내용을 나타내는 필드입니다.
    private String question;

    // Q&A 답변 내용을 나타내는 필드입니다.
    private String answer;

    // Q&A 작성자 이름을 나타내는 필드입니다.
    private String authorName;

    // 답변 여부를 표시하는 필드입니다. 답변이 있으면 true, 없으면 false입니다.
    private boolean answered;

    // 질문이 작성된 시간을 나타내는 필드입니다.
    private LocalDateTime askedAt;

    // 답변이 작성된 시간을 나타내는 필드입니다.
    private LocalDateTime answeredAt;

    // Q&A에 대한 대댓글 목록을 나타냅니다. 'ProductQnaReply' 엔티티와 일대다 관계를 형성합니다.
    @OneToMany(mappedBy = "parentQna", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<ProductQnaReply> replies = new ArrayList<>();

    // 엔티티가 영속화되기 전(데이터베이스에 저장되기 전)에 자동으로 호출되는 메서드입니다.
    // 질문 작성 시간과 답변 작성 시간을 현재 시간으로 설정합니다.
    @PrePersist
    public void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        askedAt = now;
        answeredAt = now;
    }

    // 질문에 대한 답변을 설정하는 메서드입니다. 답변 내용을 설정하고, 답변 여부를 true로 변경합니다.
    public void answerQuestion(String answer) {
        this.answer = answer;
        this.answered = true;
    }
}
