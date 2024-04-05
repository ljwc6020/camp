package com.camp.service;

import com.camp.domain.ProductQna;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.dto.ProductQnaDTO;
import com.camp.repository.ProductQnaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class ProductQnaServiceImpl implements ProductQnaService {

    private final ProductQnaRepository qnaRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public Long register(ProductQnaDTO qnaDTO) {
        log.info("Registering new Q&A: {}", qnaDTO);

        ProductQna qna = modelMapper.map(qnaDTO, ProductQna.class);
        qna = qnaRepository.save(qna);

        return qna.getQno();
    }

    @Override
    @Transactional(readOnly = true)
    public ProductQnaDTO get(Long qno) {
        log.info("Fetching Q&A with QNO: {}", qno);

        ProductQna qna = qnaRepository.findById(qno)
                .orElseThrow(() -> new IllegalArgumentException("Q&A not found with QNO: " + qno));

        return modelMapper.map(qna, ProductQnaDTO.class);
    }

    @Override
    @Transactional
    public void modify(ProductQnaDTO qnaDTO) {
        log.info("Updating Q&A: {}", qnaDTO);

        ProductQna qna = qnaRepository.findById(qnaDTO.getQno())
                .orElseThrow(() -> new IllegalArgumentException("Q&A not found with QNO: " + qnaDTO.getQno()));

        qna.setQuestion(qnaDTO.getQuestion());
        qna.setAnswer(qnaDTO.getAnswer());
        qna.setAnswered(qnaDTO.isAnswered());
        qnaRepository.save(qna);
    }

    @Override
    @Transactional
    public void remove(Long qno) {
        log.info("Deleting Q&A with QNO: {}", qno);
        qnaRepository.deleteById(qno);
    }

    @Override
    @Transactional(readOnly = true)
    public PageResponseDTO<ProductQnaDTO> getQnaList(Long pno, PageRequestDTO pageRequestDTO) {
        Pageable pageable = PageRequest.of(pageRequestDTO.getPage() - 1, pageRequestDTO.getSize(), Sort.by("qno").descending());

        Page<ProductQna> result = qnaRepository.findByProductPno(pno, pageable);

        List<ProductQnaDTO> dtoList = result.getContent().stream()
                .map(qna -> modelMapper.map(qna, ProductQnaDTO.class))
                .collect(Collectors.toList());

        // PageResponseDTO 객체 생성을 위한 빌더 패턴 사용
        return PageResponseDTO.<ProductQnaDTO>withAll()
                .dtoList(dtoList)
                .pageRequestDTO(pageRequestDTO)
                .totalCount((int) result.getTotalElements())
                .build();
    }

}
