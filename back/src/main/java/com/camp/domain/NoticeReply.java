package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "tbl_notice_reply")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString (exclude = "noticeBoard")
public class NoticeReply {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long nrno;

    // FetchType.EAGER,이건 바로 가져오기
    @ManyToOne(fetch = FetchType.LAZY)  // Many: NoticeReply, One: NoticeBoard
    private NoticeBoard noticeBoard;

    private String replyText;

    private String replyer;

    private LocalDateTime registeredAt; // 등록 시간 필드 추가

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        registeredAt = now;
    }

    public void changeText(String text){
        this.replyText = text;
    }
}