package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

// Lombok 어노테이션을 사용하여 getter, setter, toString 등의 메서드를 자동으로 생성합니다.
@Data
// 이 클래스의 인스턴스가 JPA 엔티티임을 나타내고, 데이터베이스 테이블에 매핑됩니다.
@Entity
// 이 엔티티가 매핑될 데이터베이스 테이블의 이름을 지정합니다.
@Table(name = "tbl_product_qna_reply")
// 기본 생성자를 자동으로 생성합니다.
@NoArgsConstructor
// 모든 필드를 포함한 생성자를 자동으로 생성합니다.
@AllArgsConstructor
// 빌더 패턴을 사용하여 객체 생성 시 안전성과 가독성을 높이는 메서드를 자동으로 생성합니다.
@Builder
public class ProductQnaReply {

    // 대댓글의 고유 번호입니다. 데이터베이스에서 자동으로 생성되는 ID 값입니다.
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long replyId;

    // 대댓글이 속한 부모 Q&A를 나타냅니다. 'ProductQna' 엔티티와 다대일 관계를 형성합니다.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_qna_id") // 외래 키 컬럼을 지정합니다.
    private ProductQna parentQna;

    // 대댓글 내용을 나타내는 필드입니다.
    private String replyContent;

    // 대댓글 작성자 이름을 나타내는 필드입니다.
    private String authorName;

    // 대댓글이 작성된 시간을 나타내는 필드입니다.
    private LocalDateTime repliedAt;

    // 엔티티가 영속화되기 전(데이터베이스에 저장되기 전)에 자동으로 호출되는 메서드입니다.
    // 대댓글 작성 시간을 현재 시간으로 설정합니다.
    @PrePersist
    public void onCreate() {
        repliedAt = LocalDateTime.now();
    }
}
