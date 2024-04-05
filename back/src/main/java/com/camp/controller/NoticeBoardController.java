package com.camp.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.camp.dto.NoticeBoardDTO;
import com.camp.dto.PageRequestDTO;
import com.camp.dto.PageResponseDTO;
import com.camp.service.NoticeBoardService;
import com.camp.util.CustomFileUtil;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/noticeboard")
public class NoticeBoardController {

    private final NoticeBoardService service;

    private final CustomFileUtil customFileUtil;

    @GetMapping(value ="/{nbno}")
    public NoticeBoardDTO get(@PathVariable(name="nbno") Long nbno) {

        NoticeBoardDTO noticeBoardDTO = service.get(nbno);

        return noticeBoardDTO;
    }

    @GetMapping("/list")
    public PageResponseDTO<NoticeBoardDTO> list(String writer, String title, PageRequestDTO pageRequestDTO) {

        log.info(pageRequestDTO);

        PageResponseDTO<NoticeBoardDTO> responseDTO = service.list(writer, title, pageRequestDTO);

        return responseDTO;
    }


    @PreAuthorize("hasAnyRole('ADMIN')")
    @PostMapping("/")
    public Map<String, Long> register(@RequestBody NoticeBoardDTO noticeBoardDTO) {
        log.info("NoticeBoardDTO: " + noticeBoardDTO);

        // 클라이언트로부터 전달된 파일 리스트를 가져옵니다.
        List<MultipartFile> files = noticeBoardDTO.getFiles();

        Map<String, Long> resultMap = new HashMap<>();

        // 전달된 파일 리스트가 null이 아닌 경우에만 파일 처리를 진행합니다.
        if (files != null && !files.isEmpty()) {
            List<String> uploadFileNames = customFileUtil.saveFiles(files);

            // 저장된 파일 이름 리스트를 DTO에 설정합니다.
            noticeBoardDTO.setUploadFileNames(uploadFileNames);
        }

        // 서비스를 호출하여 등록하고 결과를 응답 맵에 설정합니다.
        Long nbno = service.register(noticeBoardDTO);

log.info(noticeBoardDTO);

        return Map.of("register",nbno);
    }
    @PreAuthorize("#noticeBoardDTO.writer == authentication.name")
    @PutMapping(value = "/{nbno}")
    public Map<String, String> modify(
            @PathVariable(name="nbno") Long nbno,
            @RequestBody NoticeBoardDTO noticeBoardDTO) {

        noticeBoardDTO.setNbno(nbno);

        log.info("Modify: " + noticeBoardDTO);

        // 업로드한 파일이 있다면 파일 정보 처리
        if (noticeBoardDTO.getFiles() != null && !noticeBoardDTO.getFiles().isEmpty()) {
            List<String> uploadFileNames = customFileUtil.saveFiles(noticeBoardDTO.getFiles());
            noticeBoardDTO.setUploadFileNames(uploadFileNames);
        }

        service.modify(noticeBoardDTO);

        return Map.of("RESULT", "SUCCESS");
    }

    @PreAuthorize("#noticeBoardDTO.writer == authentication.name")
    @DeleteMapping(value = "/{nbno}")
    public Map<String, String> remove(@PathVariable(name="nbno") Long nbno,
                                      @RequestBody NoticeBoardDTO noticeBoardDTO) {

        noticeBoardDTO.setNbno(nbno);


        log.info("Remove:  " + noticeBoardDTO.getNbno());

        // 데이터가 존재하는지 확인
        Optional<NoticeBoardDTO> optionalData = Optional.ofNullable(service.get(noticeBoardDTO.getNbno()));
        if (optionalData.isPresent()) {
            List<String> oldFileNames = optionalData.get().getUploadFileNames();

            service.remove(noticeBoardDTO.getNbno());

            customFileUtil.deleteFiles(oldFileNames);

            return Map.of("RESULT", "SUCCESS");
        } else {
            // 데이터가 존재하지 않는 경우 처리
            return Map.of("RESULT", "FAILURE", "MESSAGE", "Data not found for nbno: " + noticeBoardDTO.getNbno());
        }
    }
}
