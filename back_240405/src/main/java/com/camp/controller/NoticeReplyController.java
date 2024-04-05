package com.camp.controller;


import com.camp.dto.NoticeReplyDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.service.NoticeReplyService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/reply")
@Log4j2
@RequiredArgsConstructor
public class NoticeReplyController {

    private final NoticeReplyService replyService;


    @Operation(summary = "Replies POST", description = "POST 방식으로 댓글 등록")
    @PostMapping(value = "/", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Long> register(@Valid @RequestBody NoticeReplyDTO replyDTO,
                                      BindingResult bindingResult)throws BindException {

        log.info(replyDTO);

        if(bindingResult.hasErrors()){
            throw new BindException(bindingResult);
        }

        Map<String, Long> resultMap = new HashMap<>();

        Long nrno = replyService.register(replyDTO);

        resultMap.put("nrno", nrno);

        return resultMap;
    }
    @Operation(summary = "Replies of list",
            description = "GET 방식으로 특정 게시물의 댓글 목록")
    @GetMapping(value = "/list/{nbno}")
    public PageResponseDTO<NoticeReplyDTO> getList(@PathVariable("nbno") Long nbno,
                                                   PageRequestDTO pageRequestDTO){

        PageResponseDTO<NoticeReplyDTO> responseDTO =
                replyService.getListOfBoard(nbno, pageRequestDTO);

        return responseDTO;
    }

    @Operation(summary = "Read Reply", description = "GET 방식으로 특정 댓글 조회")
    @GetMapping(value = "/{nrno}")
    public NoticeReplyDTO getReplyDTO(@PathVariable("nrno") Long nrno){

        NoticeReplyDTO replyDTO = replyService.read(nrno);

        return replyDTO;
    }

//    @PreAuthorize("#itemDTO.email == authentication.name")
    @Operation(summary = "Delete Reply", description = "DELETE 방식으로 특정 댓글 삭제")
    @DeleteMapping(value = "/{nrno}")
    public Map<String, Long> remove(@PathVariable("nrno") Long nrno){

        replyService.remove(nrno);

        Map<String, Long> resultMap = new HashMap<>();

        resultMap.put("nrno", nrno);

        return resultMap;
    }


//    @PreAuthorize("#itemDTO.email == authentication.name")
    @Operation(summary = "Modify Reply", description = "PUT 방식으로 특정 댓글 수정")
    @PutMapping(value = "/{nrno}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Long> modify(@PathVariable("nrno") Long nrno,
                                    @RequestBody NoticeReplyDTO replyDTO){

        replyDTO.setNrno(nrno);//번호를 일치 시킴

        replyService.modify(replyDTO);

        Map<String, Long> resultMap = new HashMap<>();

        resultMap.put("nrno", nrno);

        return resultMap;
    }
}