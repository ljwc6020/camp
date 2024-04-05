package com.camp.controller;


import com.camp.dto.ProductDTO;
import com.camp.dto.ProductReviewDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.service.NoticeReplyService;
import com.camp.service.ProductReviewService;
import com.camp.util.CustomFileUtil;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/review")
@Log4j2
@RequiredArgsConstructor
public class ProductReviewController {

    private final ProductReviewService reviewService;
    private final CustomFileUtil customFileUtil;


    @PostMapping("/")
    public Map<String, Long> register(ProductReviewDTO reviewDTO,
                                       BindingResult bindingResult)throws BindException {

        log.info(reviewDTO);

        if(bindingResult.hasErrors()){
            throw new BindException(bindingResult);
        }

        List<MultipartFile> files = reviewDTO.getFiles();

        List<String> uploadFileNames = customFileUtil.saveFiles(files);

        reviewDTO.setUploadFileNames(uploadFileNames);

        Map<String, Long> resultMap = new HashMap<>();

        Long prno = reviewService.register(reviewDTO);

        resultMap.put("prno", prno);

        return resultMap;
    }


    @GetMapping(value = "/list/{pno}")
    public PageResponseDTO<ProductReviewDTO> getList(@PathVariable(name="pno") Long pno,
                                                     PageRequestDTO pageRequestDTO){

        PageResponseDTO<ProductReviewDTO> responseDTO =
                reviewService.getListOfBoard(pno, pageRequestDTO);

        return responseDTO;
    }

    @GetMapping(value = "/read/{prno}")
    public ProductReviewDTO getReviewDTO(@PathVariable(name="prno") Long prno){

        ProductReviewDTO reviewDTO = reviewService.read(prno);

        return reviewDTO;
    }

    @PreAuthorize("#reviewDTO.reviewer == authentication.name")
    @DeleteMapping(value = "/{prno}")
    public Map<String, Long> remove(@PathVariable(name="prno") Long prno, @RequestBody ProductReviewDTO reviewDTO){

        reviewDTO.setPrno(prno);

        //삭제해야할 파일들 알아내기
        List<String> oldFileNames =  reviewService.read(prno).getUploadFileNames();
        // 삭제 기능 수행
        reviewService.remove(reviewDTO.getPrno());
        // 파일 삭제
        customFileUtil.deleteFiles(oldFileNames);

        Map<String, Long> resultMap = new HashMap<>();

        resultMap.put("prno", prno);

        return resultMap;
    }

    @GetMapping("/view/{fileName}")
    public ResponseEntity<Resource> viewFileGET(@PathVariable String fileName){

        return customFileUtil.getFile(fileName);

    }

    @PreAuthorize("#reviewDTO.reviewer == authentication.name")
    @PutMapping(value = "/{prno}")
    public Map<String, Long> modify(@PathVariable(name="prno") Long prno,
                                    ProductReviewDTO reviewDTO){

        reviewDTO.setPrno(prno);//번호를 일치 시킴

        // 업로드한 파일이 있다면 파일 정보 처리
        if (reviewDTO.getFiles() != null && !reviewDTO.getFiles().isEmpty()) {
            List<String> uploadFileNames = customFileUtil.saveFiles(reviewDTO.getFiles());
            reviewDTO.setUploadFileNames(uploadFileNames);
        }
        // 리뷰 수정 서비스 호출
        reviewService.modify(reviewDTO);
        log.info(reviewDTO);
        Map<String, Long> resultMap = new HashMap<>();
        log.info(reviewDTO);
        resultMap.put("prno", prno);
        log.info(reviewDTO);
        return resultMap;
    }
}