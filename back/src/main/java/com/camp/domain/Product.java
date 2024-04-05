package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "tbl_product")
@Getter
@ToString(exclude = "imageList")
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long pno;

    private String pname;

    private int price;

    private String pdesc;

    private boolean delFlag;

    private int totalReviews; // 총 리뷰 수

    private int totalQna; // 총 Q&A 수

    @Builder.Default
    // ProductReview 엔티티와의 일대다 관계 정의
    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ProductReview> reviews = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ProductQna> productQna = new ArrayList<>(); // 상품 Q&A 리스트


    public void changeDel(boolean delFlag) {
        this.delFlag = delFlag;
    }


    @ElementCollection
    @Builder.Default
    private List<com.camp.domain.ProductImage> imageList = new ArrayList<>();

    public void changePrice(int price) {
        this.price = price;
    }

    public void changeDesc(String desc){
        this.pdesc = desc;
    }

    public void changeName(String name){
        this.pname = name;
    }

    public void addImage(ProductImage image) {

        image.setOrd(this.imageList.size());
        imageList.add(image);
    }

    public void addImageString(String fileName){

        ProductImage productImage = ProductImage.builder()
                .fileName(fileName)
                .build();
        addImage(productImage);

    }

    public void updateTotalReviews() {
        this.totalReviews= this.reviews.size();
    }

    public void clearList() {
        this.imageList.clear();
    }
}