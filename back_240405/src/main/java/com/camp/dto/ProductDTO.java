package com.camp.dto;
import lombok.*;
import java.util.*;
import org.springframework.web.multipart.MultipartFile;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ProductDTO {

    private Long pno; // 상품 번호

    private String pname; // 상품 이름

    private int price; // 상품 가격

    private String pdesc; // 상품 설명

    private boolean delFlag; // 삭제 플래그

    @Builder.Default
    private List<MultipartFile> files = new ArrayList<>(); // 업로드된 파일 리스트

    @Builder.Default
    private List<String> uploadFileNames = new ArrayList<>(); // 업로드된 파일 이름 리스트

}
