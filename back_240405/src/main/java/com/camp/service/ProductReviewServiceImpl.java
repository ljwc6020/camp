package com.camp.service;


import com.camp.domain.Product;
import com.camp.domain.ProductReview;
import com.camp.domain.ProductReviewImage;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductDTO;
import com.camp.dto.ProductReviewDTO;
import com.camp.repository.ProductReviewRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;


import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
@Log4j2
public class ProductReviewServiceImpl implements ProductReviewService{

    private final ProductReviewRepository reviewRepository;

    private final ProductService productService;

    private final ModelMapper modelMapper;

    @Override
    public Long register(ProductReviewDTO reviewDTO) {

        ProductReview review = modelMapper.map(reviewDTO, ProductReview.class);


        //업로드 처리가 끝난 파일들의 이름 리스트
        List<String> uploadFileNames = reviewDTO.getUploadFileNames();

        uploadFileNames.stream().forEach(uploadName -> {
            review.addImageString(uploadName);
        });

        // Product가 null이 아닌 경우에만 처리
        if (review.getProduct() != null) {
            Long prno = reviewRepository.save(review).getPrno();
            productService.updateTotalReviews(review.getProduct().getPno());
            return prno;
        } else {
            // Product가 null인 경우에 대한 예외 처리
            throw new IllegalArgumentException("Product cannot be null");
        }
    }

    @Override
    public ProductReviewDTO read(Long prno){
        Optional<ProductReview> reviewOptional = reviewRepository.selectOne(prno);

        ProductReview review = reviewOptional.orElseThrow();

        // ProductReviewDTO로 매핑하기 전에 이미지 리스트를 파일명 리스트로 변환
        List<String> fileNameList = review.getReviewImageList().stream()
                .map(ProductReviewImage::getFileName)
                .collect(Collectors.toList());

        // ProductReviewDTO로 매핑
        ProductReviewDTO productReviewDTO = modelMapper.map(review, ProductReviewDTO.class);

        // 파일명 리스트를 ProductReviewDTO에 설정
        productReviewDTO.setUploadFileNames(fileNameList);

        return productReviewDTO;
    }

    @Override
    public void modify(ProductReviewDTO reviewDTO) {
        // Step 1: 리뷰 번호에 해당하는 리뷰를 찾음
        Optional<ProductReview> result = reviewRepository.findById(reviewDTO.getPrno());
        ProductReview review = result.orElseThrow(() -> new IllegalArgumentException("리뷰를 찾을 수 없습니다."));

        // Step 2: 리뷰 내용 변경, 별점 변경
        review.changeText(reviewDTO.getReviewText());
        review.changeScore(reviewDTO.getScore());
        // Step 3: 업로드된 파일 목록 업데이트

        review.clearList(); // 기존 파일 목록 초기화

        List<String> uploadFileNames = reviewDTO.getUploadFileNames();

        if (uploadFileNames != null && !uploadFileNames.isEmpty()) {
            uploadFileNames.forEach(uploadName -> review.addImageString(uploadName));
        }

        // 리뷰 저장
        reviewRepository.save(review);
    }

    @Override
    public void remove(Long prno){

        // nrno 로 nbno 를 찾아옴
        Long nbno = reviewRepository.findPnoByPrno(prno)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 댓글이 없습니다: " + prno));

        reviewRepository.deleteById(prno);
        // nbno 로 삭제후 총 댓글수 업데이트
        productService.updateTotalReviews(nbno);

    }


    @Override
    public PageResponseDTO<ProductReviewDTO> getListOfBoard(Long pno, PageRequestDTO pageRequestDTO) {

        Pageable pageable = PageRequest.of(
                pageRequestDTO.getPage() - 1,
                pageRequestDTO.getSize(),
                Sort.by("prno").descending());


        Page<Object[]> result = reviewRepository.listOfBoard(pno, pageable);

        List<ProductReviewDTO> dtoList = result.getContent().stream()
                .map(arr -> {
                    ProductReview review = (ProductReview) arr[0];
                    ProductReviewImage imageList = (ProductReviewImage) arr[1];
                    ProductReviewDTO dto = modelMapper.map(review, ProductReviewDTO.class);

                    if (imageList != null) {
                        dto.setUploadFileNames(Collections.singletonList(imageList.getFileName()));
                    }

                    return dto;
                })
                .collect(Collectors.toList());

        return PageResponseDTO.<ProductReviewDTO>withAll()
                .pageRequestDTO(pageRequestDTO)
                .dtoList(dtoList)
                .totalCount((int) result.getTotalElements())
                .build();
    }
}