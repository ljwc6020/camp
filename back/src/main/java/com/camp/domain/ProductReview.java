package com.camp.domain;


import jakarta.persistence.*;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "tbl_product_review")
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString (exclude = "product")
public class ProductReview {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long prno;

    // FetchType.EAGER,이건 바로 가져오기, 레이지로딩 오류가 떠서 수정
    @ManyToOne(fetch = FetchType.EAGER)
    private Product product;

    private String reviewText;

    private String reviewer;

    @Max(value = 10)
    @Min(value = 0)
    private int score;

    private LocalDateTime registeredAt; // 등록 시간 필드 추가

    private LocalDateTime modifiedAt; // 수정 시간 필드 추가

    @ElementCollection
    @Builder.Default
    private List<ProductReviewImage> reviewImageList = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        registeredAt = now;
        modifiedAt = now;
    }

    @PreUpdate // 엔티티의 변경이 일어나면 실행
    protected void onModify() {
        modifiedAt = LocalDateTime.now();
    }

    public void changeText(String text){
        this.reviewText = text;
    }

    public void changeScore(int score){this.score=score;}

    public void addImage(ProductReviewImage image) {

        image.setOrd(this.reviewImageList.size());
        reviewImageList.add(image);
    }

    public void addImageString(String fileName){

        ProductReviewImage productReviewImage = ProductReviewImage.builder()
                .fileName(fileName)
                .build();
        addImage(productReviewImage);

    }

    public void clearList() {
        this.reviewImageList.clear();
    }
}
