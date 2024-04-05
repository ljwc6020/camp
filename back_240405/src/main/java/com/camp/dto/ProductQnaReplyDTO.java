package com.camp.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProductQnaReplyDTO {
    private Long replyId; // 대댓글의 고유 식별자
    private Long parentQnaId; // 부모 댓글(상품 Q&A)의 고유 번호
    private String replyContent; // 대댓글 내용
    private String authorName; // 대댓글을 작성한 사용자의 이름
}
