package com.camp.service;


import com.camp.domain.NoticeReply;
import com.camp.dto.NoticeReplyDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.repository.NoticeReplyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
@Log4j2
public class NoticeReplyServiceImpl implements NoticeReplyService{

    private final NoticeReplyRepository replyRepository;

    private final NoticeBoardService boardService;

    private final ModelMapper modelMapper;

    @Override
    public Long register(NoticeReplyDTO replyDTO) {
        NoticeReply reply = modelMapper.map(replyDTO, NoticeReply.class);
        Long nrno = replyRepository.save(reply).getNrno();

        // 댓글 생성 시 해당 게시글의 총 댓글 수 업데이트
        boardService.updateTotalReplies(replyDTO.getNbno());

        return nrno;

    }

    @Override
    public NoticeReplyDTO read(Long nrno){
        Optional<NoticeReply> replyOptional = replyRepository.findById(nrno);

        NoticeReply reply = replyOptional.orElseThrow();

        return modelMapper.map(reply, NoticeReplyDTO.class);
    }

    @Override
    public void modify(NoticeReplyDTO noticeReplyDTO){
        Optional<NoticeReply> replyOptional = replyRepository.findById(noticeReplyDTO.getNrno());

        NoticeReply reply = replyOptional.orElseThrow();

        reply.changeText(noticeReplyDTO.getReplyText());// 댓글의 내용만 수정 가능

        replyRepository.save(reply);
    }

    public void remove(Long nrno){

        // nrno 로 nbno 를 찾아옴
        Long nbno = replyRepository.findNbnoByNrno(nrno)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 댓글이 없습니다: " + nrno));

        replyRepository.deleteById(nrno);
        // nbno 로 삭제후 총 댓글수 업데이트
        boardService.updateTotalReplies(nbno);

    }


    @Override
    public PageResponseDTO<NoticeReplyDTO> getListOfBoard(Long nbno, PageRequestDTO pageRequestDTO){

        Pageable pageable = PageRequest.of(pageRequestDTO.getPage() <=0?
                        0: pageRequestDTO.getPage() -1,
                pageRequestDTO.getSize(),
                Sort.by("nrno").ascending());

        Page<NoticeReply> result = replyRepository.listOfBoard(nbno, pageable);

        List<NoticeReplyDTO> dtoList = result.getContent().stream()
                .map(reply -> modelMapper.map(reply, NoticeReplyDTO.class))
                .collect(Collectors.toList());

        return PageResponseDTO.<NoticeReplyDTO>withAll()
                .pageRequestDTO(pageRequestDTO)
                .dtoList(dtoList)
                .totalCount((int)result.getTotalElements())
                .build();
    }
}