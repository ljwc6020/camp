package com.camp.service;

import com.camp.domain.NoticeBoard;
import com.camp.domain.NoticeBoardImage;
import com.camp.dto.NoticeBoardDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.repository.NoticeBoardRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
@Log4j2
@RequiredArgsConstructor  // 생성자 자동 주입
public class NoticeBoardServiceImpl implements NoticeBoardService {

    private final ModelMapper modelMapper;

    private final NoticeBoardRepository noticeBoardRepository;



    @Override
    public Long register(NoticeBoardDTO noticeBoardDTO) {
        NoticeBoard noticeBoard = modelMapper.map(noticeBoardDTO, NoticeBoard.class);

        // 업로드된 파일 이름 리스트를 가져옵니다.
        List<String> uploadFileNames = noticeBoardDTO.getUploadFileNames();

        // 업로드된 파일 이름 리스트가 null이 아닌 경우에만 처리합니다.
        if (uploadFileNames != null) {
            uploadFileNames.stream().forEach(uploadName -> {
                noticeBoard.addImageString(uploadName);
            });
        }

        Long nbno = noticeBoardRepository.save(noticeBoard).getNbno();
        log.info(nbno);
        return nbno;
    }

    @Override
    public NoticeBoardDTO get(Long nbno) {

        java.util.Optional<NoticeBoard> result = noticeBoardRepository.findById(nbno);

        NoticeBoard noticeBoard = result.orElseThrow();

        List<String> fileNameList = noticeBoard.getBoardImageList().stream()
                .map(NoticeBoardImage::getFileName)
                .collect(Collectors.toList());

        NoticeBoardDTO dto = modelMapper.map(noticeBoard, NoticeBoardDTO.class);

        dto.setUploadFileNames(fileNameList);

        return dto;
    }

    @Override
    public void modify(NoticeBoardDTO noticeBoardDTO) {

        Optional<NoticeBoard> result = noticeBoardRepository.findById(noticeBoardDTO.getNbno());

        NoticeBoard noticeBoard = result.orElseThrow();
        noticeBoard.changeTitle(noticeBoardDTO.getTitle());
        noticeBoard.changeContent(noticeBoardDTO.getContent());

        noticeBoard.clearList(); // 기존 파일 목록 초기화

        List<String> uploadFileNames = noticeBoardDTO.getUploadFileNames();

        if (uploadFileNames != null && !uploadFileNames.isEmpty()) {
            uploadFileNames.forEach(uploadName -> noticeBoard.addImageString(uploadName));
        }

        noticeBoardRepository.save(noticeBoard);

    }

    @Override
    public void remove(Long nbno) {

        noticeBoardRepository.deleteById(nbno);

    }

    @Override
    public PageResponseDTO<NoticeBoardDTO> list(String writer, String title, PageRequestDTO pageRequestDTO ) {
        Pageable pageable =
                PageRequest.of(
                        pageRequestDTO.getPage() - 1,  // 1페이지가 0이므로 주의
                        pageRequestDTO.getSize(),
                        Sort.by("nbno").descending());

        Page<Object[]> result = noticeBoardRepository.selectList(writer,title,pageable);

        List<NoticeBoardDTO> dtoList = result.getContent().stream()
                .map(arr -> {
                    NoticeBoard noticeBoard = (NoticeBoard) arr[0];
                    NoticeBoardImage boardImageList = (NoticeBoardImage) arr[1];

                    NoticeBoardDTO dto = modelMapper.map(noticeBoard, NoticeBoardDTO.class);
                    if (boardImageList != null) {
                        dto.setUploadFileNames(Collections.singletonList(boardImageList.getFileName()));
                    }
                    return dto;
                })
                .collect(Collectors.toList());

        return PageResponseDTO.<NoticeBoardDTO>withAll()
                .pageRequestDTO(pageRequestDTO)
                .dtoList(dtoList)
                .totalCount((int) result.getTotalElements())
                .build();
    }

    @Override
    public void updateTotalReplies(Long nbno) {
        NoticeBoard noticeBoard = noticeBoardRepository.findById(nbno)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 공지사항이: " + nbno));

        int totalReplies = noticeBoard.getReplies().size();
        noticeBoard.updateTotalReplies();

        noticeBoardRepository.save(noticeBoard);
    }

}



