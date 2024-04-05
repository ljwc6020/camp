package com.camp.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "tbl_board")
@Getter
@ToString(exclude = "boardImageList")
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class NoticeBoard {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long nbno;

    private String title;

    private String writer;

    private String content;

    private int totalReplies; // 총 댓글 수
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDateTime registeredAt; // 등록 시간 필드 추가
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDateTime modifiedAt; // 수정 시간 필드 추가

    @ElementCollection
    @Builder.Default
    private List<NoticeBoardImage> boardImageList = new ArrayList<>();

    @Builder.Default
    // NoticeReply 엔티티와의 일대다 관계 정의
    @OneToMany(mappedBy = "noticeBoard", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NoticeReply> replies = new ArrayList<>();
    // 총 댓글수 업데이트
    public void updateTotalReplies() {
        this.totalReplies = this.replies.size();
    }


    public void changeTitle(String title){
        this.title = title;
    }

    public void changeContent(String content){
        this.content=content;
    }

    // 서버에서 현재 시간으로 등록 시간 설정, 엔티티 등록 전에 실행
    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        registeredAt = now;
        modifiedAt = now; // 생성 시간과 동일하게 설정
    }

    @PreUpdate // 엔티티의 변경이 일어나면 실행
    protected void onModify() {
        modifiedAt = LocalDateTime.now();
    }


    public void addImage(NoticeBoardImage image) {

        image.setOrd(this.boardImageList.size());
        boardImageList.add(image);
    }

    public void addImageString(String fileName){

        NoticeBoardImage noticeBoardImage = NoticeBoardImage.builder()
                .fileName(fileName)
                .build();
        addImage(noticeBoardImage);

    }

    public void clearList() {
        this.boardImageList.clear();
    }
}